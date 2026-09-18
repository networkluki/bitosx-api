using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using BitosX.Contracts.Accounts;

namespace BitosX.Api.Tests;

/// <summary>
/// End-to-end Phase 2D.1 rate-limit + client-IP trust tests against bitosx_test with hardening enabled.
/// Client IP is controlled deterministically via X-Test-Peer-Ip (simulated TCP peer) + X-Forwarded-For.
/// Each test uses unique client IPs/emails so the process-wide limiter state does not leak between tests.
/// </summary>
public sealed class AuthRateLimitTests : IClassFixture<HardenedAuthApiFactory>, IAsyncLifetime
{
    private const string ValidPassword = "Correct-Horse-Battery-Staple-1";

    private readonly HardenedAuthApiFactory _factory;

    public AuthRateLimitTests(HardenedAuthApiFactory factory) => _factory = factory;

    public async Task InitializeAsync() => await _factory.ResetDatabaseAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    private static int _ipCounter;
    private static string ClientIp() { var n = Interlocked.Increment(ref _ipCounter); return $"10.{(n >> 16) & 0xff}.{(n >> 8) & 0xff}.{n & 0xff}"; }
    private static string PublicIp() { var n = Interlocked.Increment(ref _ipCounter); return $"198.51.100.{n & 0xff}"; }
    private static string Email() => $"u-{Guid.NewGuid():N}@example.com";

    private Task<HttpResponseMessage> LoginAsync(string email, string? xff, string peer = "127.0.0.1", string password = ValidPassword)
        => HardenedAuthApiFactory.SendAsync(_factory.CreateClient(), HttpMethod.Post, "/v1/auth/login", new { email, password }, peer, xff);

    private Task<HttpResponseMessage> RefreshAsync(string refreshToken, string? xff, string peer = "127.0.0.1")
        => HardenedAuthApiFactory.SendAsync(_factory.CreateClient(), HttpMethod.Post, "/v1/auth/refresh", new { refreshToken }, peer, xff);

    // ---- client IP trust chain ----

    [Fact]
    public async Task TrustedLoopbackProxy_KeysByForwardedClientIp()
    {
        var clientA = ClientIp();
        for (var i = 0; i < 10; i++)
        {
            Assert.NotEqual(HttpStatusCode.TooManyRequests, (await LoginAsync(Email(), clientA)).StatusCode);
        }

        // 11th from the same forwarded client IP is limited...
        Assert.Equal(HttpStatusCode.TooManyRequests, (await LoginAsync(Email(), clientA)).StatusCode);
        // ...but a different forwarded client IP has its own bucket.
        Assert.NotEqual(HttpStatusCode.TooManyRequests, (await LoginAsync(Email(), ClientIp())).StatusCode);
    }

    [Fact]
    public async Task SpoofedForwardedFor_FromUntrustedPeer_IsIgnored()
    {
        var spoof = ClientIp();          // same X-Forwarded-For value on every request
        var peerA = PublicIp();
        for (var i = 0; i < 10; i++)
        {
            Assert.NotEqual(HttpStatusCode.TooManyRequests, (await LoginAsync(Email(), spoof, peer: peerA)).StatusCode);
        }

        Assert.Equal(HttpStatusCode.TooManyRequests, (await LoginAsync(Email(), spoof, peer: peerA)).StatusCode);

        // Same spoofed XFF but a different untrusted peer → different bucket → NOT limited.
        // This proves the untrusted peer's X-Forwarded-For was ignored (peer address is authoritative).
        Assert.NotEqual(HttpStatusCode.TooManyRequests, (await LoginAsync(Email(), spoof, peer: PublicIp())).StatusCode);
    }

    [Fact]
    public async Task IPv4MappedIPv6_DoesNotCreateDuplicateBucket()
    {
        var v4 = ClientIp();
        var mapped = "::ffff:" + v4;
        for (var i = 0; i < 10; i++)
        {
            var xff = i % 2 == 0 ? v4 : mapped; // alternate representations of the SAME address
            Assert.NotEqual(HttpStatusCode.TooManyRequests, (await LoginAsync(Email(), xff)).StatusCode);
        }

        Assert.Equal(HttpStatusCode.TooManyRequests, (await LoginAsync(Email(), mapped)).StatusCode);
    }

    [Fact]
    public async Task UnresolvableClientIp_HardenedMode_FailsClosed503()
    {
        // Trusted loopback peer with NO forwarded client IP → resolved address is loopback → 503.
        var resp = await LoginAsync(Email(), xff: null, peer: "127.0.0.1");
        Assert.Equal(HttpStatusCode.ServiceUnavailable, resp.StatusCode);
    }

    // ---- login per-IP ----

    [Fact]
    public async Task LoginPerIp_BurstThenReject_AndRetryAfter()
    {
        var ip = ClientIp();
        for (var i = 0; i < 10; i++)
        {
            Assert.NotEqual(HttpStatusCode.TooManyRequests, (await LoginAsync(Email(), ip)).StatusCode);
        }

        var limited = await LoginAsync(Email(), ip);
        Assert.Equal(HttpStatusCode.TooManyRequests, limited.StatusCode);

        using var body = JsonDocument.Parse(await limited.Content.ReadAsStringAsync());
        Assert.Equal("Too Many Requests", body.RootElement.GetProperty("title").GetString());
        Assert.Equal("Too many requests. Try again later.", body.RootElement.GetProperty("detail").GetString());
        Assert.NotNull(limited.Headers.RetryAfter?.Delta);
        Assert.True(limited.Headers.RetryAfter!.Delta!.Value.TotalSeconds > 0);
    }

    [Fact]
    public async Task LoginPerIp_DifferentIps_AreIndependent()
    {
        var ipA = ClientIp();
        for (var i = 0; i < 10; i++) await LoginAsync(Email(), ipA);
        Assert.Equal(HttpStatusCode.TooManyRequests, (await LoginAsync(Email(), ipA)).StatusCode);

        Assert.NotEqual(HttpStatusCode.TooManyRequests, (await LoginAsync(Email(), ClientIp())).StatusCode);
    }

    // ---- login per-email ----

    [Fact]
    public async Task LoginPerEmail_EnforcedBeforeCredentialEvaluation_EvenForValidCredentials()
    {
        var email = await _factory.CreateVerifiedAccountAsync(ValidPassword);
        var ip = ClientIp(); // per-IP limit (10) is not the binding constraint here

        for (var i = 0; i < 5; i++)
        {
            Assert.Equal(HttpStatusCode.OK, (await LoginAsync(email, ip)).StatusCode); // valid creds succeed
        }

        // 6th valid-credential attempt is rejected by the per-email limiter BEFORE credential evaluation.
        Assert.Equal(HttpStatusCode.TooManyRequests, (await LoginAsync(email, ip)).StatusCode);
    }

    [Fact]
    public async Task LoginPerEmail_UnknownAccount_SameLimit_NoEnumeration()
    {
        var unknown = Email();
        var ip = ClientIp();
        for (var i = 0; i < 5; i++)
        {
            Assert.Equal(HttpStatusCode.Unauthorized, (await LoginAsync(unknown, ip)).StatusCode);
        }

        Assert.Equal(HttpStatusCode.TooManyRequests, (await LoginAsync(unknown, ip)).StatusCode); // identical threshold to a real account
    }

    [Fact]
    public async Task LoginPerEmail_CaseEquivalentEmails_ShareOnePartition()
    {
        var lower = Email();
        var upper = lower.ToUpperInvariant();
        var ip = ClientIp();
        for (var i = 0; i < 5; i++)
        {
            await LoginAsync(i % 2 == 0 ? lower : upper, ip); // normalizer folds case → one partition
        }

        Assert.Equal(HttpStatusCode.TooManyRequests, (await LoginAsync(upper, ip)).StatusCode);
    }

    [Fact]
    public async Task LoginPerEmail_DifferentEmails_AreIndependent()
    {
        var ip = ClientIp();
        var emailA = Email();
        for (var i = 0; i < 5; i++) await LoginAsync(emailA, ip);
        Assert.Equal(HttpStatusCode.TooManyRequests, (await LoginAsync(emailA, ip)).StatusCode);

        Assert.NotEqual(HttpStatusCode.TooManyRequests, (await LoginAsync(Email(), ip)).StatusCode); // different email, own bucket
    }

    // ---- refresh per-IP ----

    [Fact]
    public async Task RefreshPerIp_BurstThenReject()
    {
        var ip = ClientIp();
        for (var i = 0; i < 30; i++)
        {
            Assert.NotEqual(HttpStatusCode.TooManyRequests, (await RefreshAsync("too-short", ip)).StatusCode);
        }

        Assert.Equal(HttpStatusCode.TooManyRequests, (await RefreshAsync("too-short", ip)).StatusCode);
        Assert.NotEqual(HttpStatusCode.TooManyRequests, (await RefreshAsync("too-short", ClientIp())).StatusCode);
    }

    [Fact]
    public async Task Refresh_ValidRotation_StillWorksUnderHardening()
    {
        var email = await _factory.CreateVerifiedAccountAsync(ValidPassword);
        var login = await LoginAsync(email, ClientIp());
        var tokens = (await login.Content.ReadFromJsonAsync<TokenResponse>())!;

        var resp = await RefreshAsync(tokens.RefreshToken, ClientIp());
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode); // rate limiting does not break refresh semantics
        var rotated = (await resp.Content.ReadFromJsonAsync<TokenResponse>())!;
        Assert.NotEqual(tokens.RefreshToken, rotated.RefreshToken);
    }

    // ---- partition-cache capacity: fail closed, never reset a live limiter ----

    private static async Task<HttpResponseMessage> LoginFrom(HardenedAuthApiFactory f, string email, string? xff, string peer = "127.0.0.1")
        => await HardenedAuthApiFactory.SendAsync(f.CreateClient(), HttpMethod.Post, "/v1/auth/login", new { email, password = ValidPassword }, peer, xff);

    [Fact]
    public async Task IpPartitionCapacityExhaustion_FailsClosed503_Generic_NoLiveReset()
    {
        using var factory = new HardenedAuthApiFactory();
        factory.Overrides["Security:PublicExposureHardening:PartitionState:MaxIpPartitions"] = "2";
        await factory.ResetDatabaseAsync();

        var ip1 = ClientIp();
        var ip2 = ClientIp();
        var ip3 = ClientIp();

        Assert.NotEqual(HttpStatusCode.ServiceUnavailable, (await LoginFrom(factory, Email(), ip1)).StatusCode);
        Assert.NotEqual(HttpStatusCode.ServiceUnavailable, (await LoginFrom(factory, Email(), ip2)).StatusCode);

        // Cache full (ip1, ip2 both non-idle) → a new IP fails closed with a generic 503.
        var overflow = await LoginFrom(factory, Email(), ip3);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, overflow.StatusCode);

        var raw = await overflow.Content.ReadAsStringAsync();
        using var body = JsonDocument.Parse(raw);
        Assert.Equal("Service unavailable", body.RootElement.GetProperty("title").GetString());
        Assert.DoesNotContain(ip3, raw, StringComparison.Ordinal); // no partition/IP disclosure

        // An existing IP still resolves against its own (live) limiter — not evicted to admit ip3.
        Assert.NotEqual(HttpStatusCode.ServiceUnavailable, (await LoginFrom(factory, Email(), ip1)).StatusCode);
    }

    [Fact]
    public async Task IpPartitionChurn_CannotResetExhaustedIpLimiter()
    {
        using var factory = new HardenedAuthApiFactory();
        factory.Overrides["Security:PublicExposureHardening:PartitionState:MaxIpPartitions"] = "2";
        await factory.ResetDatabaseAsync();

        var ipA = ClientIp();
        for (var i = 0; i < 10; i++) await LoginFrom(factory, Email(), ipA); // exhaust ipA per-IP (limit 10)
        Assert.Equal(HttpStatusCode.TooManyRequests, (await LoginFrom(factory, Email(), ipA)).StatusCode);

        // Churn: fill the remaining slot, then hammer new IPs (which fail closed) to try to evict ipA.
        await LoginFrom(factory, Email(), ClientIp());
        for (var i = 0; i < 5; i++) await LoginFrom(factory, Email(), ClientIp());

        // ipA is still exhausted — churn did not reset it.
        Assert.Equal(HttpStatusCode.TooManyRequests, (await LoginFrom(factory, Email(), ipA)).StatusCode);
    }

    [Fact]
    public async Task EmailPartitionChurn_CannotResetExhaustedEmailLimiter()
    {
        using var factory = new HardenedAuthApiFactory();
        factory.Overrides["Security:PublicExposureHardening:PartitionState:MaxEmailPartitions"] = "2";
        await factory.ResetDatabaseAsync();

        var ip = ClientIp();               // single IP (per-IP limit 10 is not the binding constraint)
        var emailA = Email();
        for (var i = 0; i < 5; i++) await LoginFrom(factory, emailA, ip); // exhaust emailA per-email (limit 5)
        Assert.Equal(HttpStatusCode.TooManyRequests, (await LoginFrom(factory, emailA, ip)).StatusCode);

        // Churn distinct emails to try to evict emailA's partition (fills slot 2, then fails closed).
        await LoginFrom(factory, Email(), ip);
        await LoginFrom(factory, Email(), ip);

        // emailA still exhausted — churn did not reset it.
        Assert.Equal(HttpStatusCode.TooManyRequests, (await LoginFrom(factory, emailA, ip)).StatusCode);
    }

    // ---- replenishment (short period override; brief real wait, not multi-minute) ----

    [Fact]
    public async Task LoginPerIp_ReplenishesAfterPeriod()
    {
        using var factory = new HardenedAuthApiFactory();
        factory.Overrides["Security:PublicExposureHardening:LoginPerIp:TokenLimit"] = "2";
        factory.Overrides["Security:PublicExposureHardening:LoginPerIp:TokensPerPeriod"] = "2";
        factory.Overrides["Security:PublicExposureHardening:LoginPerIp:ReplenishmentSeconds"] = "1";
        await factory.ResetDatabaseAsync();
        var ip = ClientIp();

        for (var i = 0; i < 2; i++)
        {
            Assert.NotEqual(HttpStatusCode.TooManyRequests,
                (await HardenedAuthApiFactory.SendAsync(factory.CreateClient(), HttpMethod.Post, "/v1/auth/login", new { email = Email(), password = ValidPassword }, "127.0.0.1", ip)).StatusCode);
        }

        Assert.Equal(HttpStatusCode.TooManyRequests,
            (await HardenedAuthApiFactory.SendAsync(factory.CreateClient(), HttpMethod.Post, "/v1/auth/login", new { email = Email(), password = ValidPassword }, "127.0.0.1", ip)).StatusCode);

        await Task.Delay(TimeSpan.FromMilliseconds(1300)); // one replenishment period

        Assert.NotEqual(HttpStatusCode.TooManyRequests,
            (await HardenedAuthApiFactory.SendAsync(factory.CreateClient(), HttpMethod.Post, "/v1/auth/login", new { email = Email(), password = ValidPassword }, "127.0.0.1", ip)).StatusCode);
    }
}
