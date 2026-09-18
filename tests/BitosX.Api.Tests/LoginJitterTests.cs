using System.Net;
using System.Net.Http.Json;
using System.Text;
using BitosX.Api.Security;

namespace BitosX.Api.Tests;

/// <summary>
/// Login-response jitter tests. HTTP tests use a recording jitter fake to prove exactly which outcomes go
/// through the jitter path (success + ordinary credential 401) and which skip it (400/413/429/503). Unit
/// tests cover the real jitter's disabled/no-op and cancellation behavior without wall-clock assertions.
/// </summary>
public sealed class LoginJitterTests
{
    private const string ValidPassword = "Correct-Horse-Battery-Staple-1";

    private static int _ip;
    private static string ClientIp() { var n = Interlocked.Increment(ref _ip); return $"10.30.{(n >> 8) & 0xff}.{n & 0xff}"; }
    private static string Email() => $"j-{Guid.NewGuid():N}@example.com";

    private static Task<HttpResponseMessage> LoginAsync(HardenedAuthApiFactory f, string email, string password, string xff)
        => HardenedAuthApiFactory.SendAsync(f.CreateClient(), HttpMethod.Post, "/v1/auth/login", new { email, password }, "127.0.0.1", xff);

    [Fact]
    public async Task Jitter_AppliedTo_Success_And_CredentialFailure_SameMechanism()
    {
        var jitter = new RecordingLoginResponseJitter();
        using var f = new HardenedAuthApiFactory { JitterOverride = jitter };
        await f.ResetDatabaseAsync();
        var email = await f.CreateVerifiedAccountAsync(ValidPassword);

        var before = jitter.Calls;
        Assert.Equal(HttpStatusCode.OK, (await LoginAsync(f, email, ValidPassword, ClientIp())).StatusCode);
        Assert.Equal(before + 1, jitter.Calls); // success went through jitter

        Assert.Equal(HttpStatusCode.Unauthorized, (await LoginAsync(f, email, "Wrong-Password-000000", ClientIp())).StatusCode);
        Assert.Equal(before + 2, jitter.Calls); // ordinary credential failure went through the same jitter
    }

    [Fact]
    public async Task Jitter_Skipped_For_400_And_413()
    {
        var jitter = new RecordingLoginResponseJitter();
        using var f = new HardenedAuthApiFactory { JitterOverride = jitter };
        await f.ResetDatabaseAsync();

        var before = jitter.Calls;

        using var malformed = new StringContent("{ nope ", Encoding.UTF8, "application/json");
        Assert.Equal(HttpStatusCode.BadRequest, (await f.CreateClient().PostAsync("/v1/auth/login", malformed)).StatusCode);

        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, (await LoginAsync(f, "a@example.com", new string('x', 5000), ClientIp())).StatusCode);

        Assert.Equal(before, jitter.Calls); // neither 400 nor 413 invoked jitter
    }

    [Fact]
    public async Task Jitter_Skipped_For_RateLimit429()
    {
        var jitter = new RecordingLoginResponseJitter();
        using var f = new HardenedAuthApiFactory { JitterOverride = jitter };
        f.Overrides["Security:PublicExposureHardening:LoginPerIp:TokenLimit"] = "1";
        f.Overrides["Security:PublicExposureHardening:LoginPerIp:TokensPerPeriod"] = "1";
        await f.ResetDatabaseAsync();

        var ip = ClientIp();
        await LoginAsync(f, Email(), ValidPassword, ip); // consumes the single per-IP token (jitter applied)
        var before = jitter.Calls;

        Assert.Equal(HttpStatusCode.TooManyRequests, (await LoginAsync(f, Email(), ValidPassword, ip)).StatusCode);
        Assert.Equal(before, jitter.Calls); // 429 skipped jitter
    }

    [Fact]
    public async Task Jitter_Skipped_For_Argon2_503()
    {
        var core = new BlockingArgon2Core();
        var jitter = new RecordingLoginResponseJitter();
        using var f = new HardenedAuthApiFactory { Argon2CoreOverride = core, JitterOverride = jitter };
        f.Overrides["Security:PublicExposureHardening:Argon2:MaxConcurrent"] = "1";
        f.Overrides["Security:PublicExposureHardening:Argon2:QueueCapacity"] = "0";
        f.Overrides["Security:PublicExposureHardening:Argon2:AcquireTimeoutMilliseconds"] = "30000";
        await f.ResetDatabaseAsync();
        var email = await f.CreateVerifiedAccountAsync(ValidPassword);

        core.Arm();
        var blocking = LoginAsync(f, email, ValidPassword, ClientIp()); // holds the permit (has not reached jitter yet)
        await core.Entered;

        var before = jitter.Calls;
        Assert.Equal(HttpStatusCode.ServiceUnavailable, (await LoginAsync(f, email, ValidPassword, ClientIp())).StatusCode);
        Assert.Equal(before, jitter.Calls); // Argon2 503 skipped jitter

        core.Release();
        await blocking;
    }

    // ---- unit tests for the real jitter component ----

    private static PublicExposureHardeningOptions Options(bool enabled, int min, int max)
    {
        var o = new PublicExposureHardeningOptions { Enabled = enabled };
        o.LoginJitter.MinMilliseconds = min;
        o.LoginJitter.MaxMilliseconds = max;
        return o;
    }

    [Fact]
    public async Task RealJitter_Disabled_CompletesImmediately()
    {
        var jitter = new LoginResponseJitter(Options(enabled: false, 1000, 2000), TimeProvider.System);
        var task = jitter.ApplyAsync(CancellationToken.None);
        Assert.True(task.IsCompleted); // no delay scheduled when disabled
        await task;
    }

    [Fact]
    public async Task RealJitter_Enabled_ZeroRange_CompletesImmediately()
    {
        var jitter = new LoginResponseJitter(Options(enabled: true, 0, 0), TimeProvider.System);
        await jitter.ApplyAsync(CancellationToken.None); // min==max==0 → no delay
    }

    [Fact]
    public async Task RealJitter_Cancellation_PropagatesPromptly()
    {
        var jitter = new LoginResponseJitter(Options(enabled: true, 10_000, 20_000), TimeProvider.System);
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await jitter.ApplyAsync(cts.Token));
    }
}
