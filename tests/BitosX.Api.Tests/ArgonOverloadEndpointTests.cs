using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using BitosX.Contracts.Accounts;

namespace BitosX.Api.Tests;

/// <summary>
/// End-to-end tests for bounded-Argon2 overload at the login boundary. A blocking Argon2 core holds the
/// single admission permit deterministically so the next login hits capacity. Overload maps to a generic
/// 503 (never 401, never a token), and genuine cancellation stays cancellation.
/// </summary>
public sealed class ArgonOverloadEndpointTests
{
    private const string ValidPassword = "Correct-Horse-Battery-Staple-1";

    private static int _ip;
    private static string ClientIp() { var n = Interlocked.Increment(ref _ip); return $"172.16.{(n >> 8) & 0xff}.{n & 0xff}"; }

    private static HardenedAuthApiFactory Factory(BlockingArgon2Core core, int maxConcurrent, int queueCapacity, int timeoutMs)
    {
        var f = new HardenedAuthApiFactory { Argon2CoreOverride = core };
        f.Overrides["Security:PublicExposureHardening:Argon2:MaxConcurrent"] = maxConcurrent.ToString();
        f.Overrides["Security:PublicExposureHardening:Argon2:QueueCapacity"] = queueCapacity.ToString();
        f.Overrides["Security:PublicExposureHardening:Argon2:AcquireTimeoutMilliseconds"] = timeoutMs.ToString();
        return f;
    }

    private static Task<HttpResponseMessage> LoginAsync(HardenedAuthApiFactory f, string email, string xff)
        => HardenedAuthApiFactory.SendAsync(f.CreateClient(), HttpMethod.Post, "/v1/auth/login", new { email, password = ValidPassword }, "127.0.0.1", xff);

    [Fact]
    public async Task QueueFull_Login_Returns503_Generic_NotAuth_NoToken()
    {
        var core = new BlockingArgon2Core();
        using var f = Factory(core, maxConcurrent: 1, queueCapacity: 0, timeoutMs: 30000);
        await f.ResetDatabaseAsync();
        var email = await f.CreateVerifiedAccountAsync(ValidPassword);

        core.Arm();
        var blocking = LoginAsync(f, email, ClientIp()); // enters Compute, holds the only permit
        await core.Entered;

        var overload = await LoginAsync(f, email, ClientIp()); // no permit, queue capacity 0 → 503

        Assert.Equal(HttpStatusCode.ServiceUnavailable, overload.StatusCode);
        Assert.Equal(TimeSpan.FromSeconds(1), overload.Headers.RetryAfter?.Delta); // Retry-After: 1
        var raw = await overload.Content.ReadAsStringAsync();
        using var body = JsonDocument.Parse(raw);
        Assert.Equal("Service unavailable", body.RootElement.GetProperty("title").GetString());
        Assert.DoesNotContain("accessToken", raw, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(email, raw, StringComparison.OrdinalIgnoreCase);

        core.Release();
        Assert.Equal(HttpStatusCode.OK, (await blocking).StatusCode); // the held login completes normally
    }

    [Fact]
    public async Task AcquireTimeout_Login_Returns503()
    {
        var core = new BlockingArgon2Core();
        using var f = Factory(core, maxConcurrent: 1, queueCapacity: 1, timeoutMs: 150);
        await f.ResetDatabaseAsync();
        var email = await f.CreateVerifiedAccountAsync(ValidPassword);

        core.Arm();
        var blocking = LoginAsync(f, email, ClientIp()); // holds the permit and never releases within 150 ms
        await core.Entered;

        var timedOut = await LoginAsync(f, email, ClientIp()); // queues, then times out → 503
        Assert.Equal(HttpStatusCode.ServiceUnavailable, timedOut.StatusCode);

        core.Release();
        await blocking;
    }

    [Fact]
    public async Task Cancellation_WhileQueued_IsNotRewrittenAs503()
    {
        var core = new BlockingArgon2Core();
        using var f = Factory(core, maxConcurrent: 1, queueCapacity: 1, timeoutMs: 30000);
        await f.ResetDatabaseAsync();
        var email = await f.CreateVerifiedAccountAsync(ValidPassword);

        core.Arm();
        var blocking = LoginAsync(f, email, ClientIp()); // holds the permit
        await core.Entered;

        using var cts = new CancellationTokenSource();
        using var request = new HttpRequestMessage(HttpMethod.Post, "/v1/auth/login")
        {
            Content = JsonContent.Create(new { email, password = ValidPassword }),
        };
        request.Headers.TryAddWithoutValidation("X-Test-Peer-Ip", "127.0.0.1");
        request.Headers.TryAddWithoutValidation("X-Forwarded-For", ClientIp());
        var queued = f.CreateClient().SendAsync(request, cts.Token); // queues waiting for the permit

        await cts.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await queued); // cancellation, not a 503 response

        core.Release();
        await blocking;
    }

    [Fact]
    public async Task BelowCapacity_Login_Unchanged_200_And_401()
    {
        var core = new BlockingArgon2Core(); // starts unblocked → normal behavior
        using var f = Factory(core, maxConcurrent: 2, queueCapacity: 4, timeoutMs: 30000);
        await f.ResetDatabaseAsync();
        var email = await f.CreateVerifiedAccountAsync(ValidPassword);

        var ok = await LoginAsync(f, email, ClientIp());
        Assert.Equal(HttpStatusCode.OK, ok.StatusCode);

        var wrong = await HardenedAuthApiFactory.SendAsync(
            f.CreateClient(), HttpMethod.Post, "/v1/auth/login", new { email, password = "Wrong-Password-000000" }, "127.0.0.1", ClientIp());
        Assert.Equal(HttpStatusCode.Unauthorized, wrong.StatusCode);
    }
}
