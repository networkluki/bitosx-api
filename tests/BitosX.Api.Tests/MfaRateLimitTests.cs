using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using BitosX.Contracts.Accounts;

namespace BitosX.Api.Tests;

/// <summary>Hardened-mode limits on the second sign-in step (per IP) and TOTP management (per account).</summary>
public sealed class MfaRateLimitTests : IClassFixture<HardenedAuthApiFactory>, IAsyncLifetime
{
    private const string ValidPassword = "Correct-Horse-Battery-Staple-1";

    private readonly HardenedAuthApiFactory _factory;

    public MfaRateLimitTests(HardenedAuthApiFactory factory) => _factory = factory;

    public async Task InitializeAsync() => await _factory.ResetDatabaseAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    private static int _ipCounter = 9_000;
    private static string ClientIp() { var n = Interlocked.Increment(ref _ipCounter); return $"10.{(n >> 16) & 0xff}.{(n >> 8) & 0xff}.{n & 0xff}"; }

    [Fact]
    public async Task LoginTotp_PerIp_EleventhIsLimited()
    {
        var ip = ClientIp();
        var client = _factory.CreateClient();
        for (var i = 0; i < 10; i++)
        {
            var resp = await HardenedAuthApiFactory.SendAsync(client, HttpMethod.Post, "/v1/auth/login/totp", new { mfaToken = new string('A', 43), code = "123456" }, "127.0.0.1", ip);
            Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
        }

        var limited = await HardenedAuthApiFactory.SendAsync(client, HttpMethod.Post, "/v1/auth/login/totp", new { mfaToken = new string('A', 43), code = "123456" }, "127.0.0.1", ip);
        Assert.Equal(HttpStatusCode.TooManyRequests, limited.StatusCode);
        Assert.NotNull(limited.Headers.RetryAfter);
    }

    [Fact]
    public async Task TotpManage_PerAccount_EleventhIsLimited()
    {
        var email = await _factory.CreateVerifiedAccountAsync(ValidPassword);
        var loginResp = await HardenedAuthApiFactory.SendAsync(_factory.CreateClient(), HttpMethod.Post, "/v1/auth/login", new { email, password = ValidPassword }, "127.0.0.1", ClientIp());
        loginResp.EnsureSuccessStatusCode();
        var tokens = (await loginResp.Content.ReadFromJsonAsync<TokenResponse>())!;
        var authed = _factory.CreateClient();
        authed.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tokens.AccessToken);

        for (var i = 0; i < 10; i++)
        {
            var resp = await HardenedAuthApiFactory.SendAsync(authed, HttpMethod.Post, "/v1/account/totp/confirm", new { code = "000000" }, "127.0.0.1", ClientIp());
            Assert.Equal(HttpStatusCode.Conflict, resp.StatusCode); // nothing pending, but each call costs a token
        }

        var limited = await HardenedAuthApiFactory.SendAsync(authed, HttpMethod.Post, "/v1/account/totp/confirm", new { code = "000000" }, "127.0.0.1", ClientIp());
        Assert.Equal(HttpStatusCode.TooManyRequests, limited.StatusCode);
    }
}

/// <summary>The per-account bound on the second sign-in step (MfaPerAccount), keyed by the account the challenge names.</summary>
public sealed class MfaPerAccountRateLimitTests
{
    private const string ValidPassword = "Correct-Horse-Battery-Staple-1";
    private static int _ipCounter = 40_000;
    private static string ClientIp() { var n = Interlocked.Increment(ref _ipCounter); return $"10.{(n >> 16) & 0xff}.{(n >> 8) & 0xff}.{n & 0xff}"; }

    [Fact]
    public async Task LoginTotp_PerAccount_IsLimited_AcrossIpsAndChallenges()
    {
        await using var factory = new HardenedAuthApiFactory();
        factory.Overrides["Security:PublicExposureHardening:MfaPerAccount:TokenLimit"] = "3";
        factory.Overrides["Security:PublicExposureHardening:MfaPerAccount:TokensPerPeriod"] = "1";
        factory.Overrides["Security:PublicExposureHardening:MfaPerAccount:ReplenishmentSeconds"] = "600";
        var email = await factory.CreateVerifiedAccountAsync(ValidPassword);

        var login = await HardenedAuthApiFactory.SendAsync(factory.CreateClient(), HttpMethod.Post, "/v1/auth/login", new { email, password = ValidPassword }, "127.0.0.1", ClientIp());
        var tokens = (await login.Content.ReadFromJsonAsync<TokenResponse>())!;
        var authed = factory.CreateClient();
        authed.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tokens.AccessToken);
        var enrolled = (await (await HardenedAuthApiFactory.SendAsync(authed, HttpMethod.Post, "/v1/account/totp/enroll", new { password = ValidPassword }, "127.0.0.1", ClientIp()))
            .Content.ReadFromJsonAsync<TotpEnrollResponse>())!;
        Assert.True(BitosX.Application.Mfa.Base32.TryDecode(enrolled.Secret, out var secret));
        var code = BitosX.Application.Mfa.Rfc6238Totp.Compute(secret, BitosX.Application.Mfa.Rfc6238Totp.Step(DateTimeOffset.UtcNow.ToUnixTimeSeconds(), 30), 6);
        (await HardenedAuthApiFactory.SendAsync(authed, HttpMethod.Post, "/v1/account/totp/confirm", new { code }, "127.0.0.1", ClientIp())).EnsureSuccessStatusCode();

        async Task<string> ChallengeAsync()
        {
            var resp = await HardenedAuthApiFactory.SendAsync(factory.CreateClient(), HttpMethod.Post, "/v1/auth/login", new { email, password = ValidPassword }, "127.0.0.1", ClientIp());
            Assert.Equal(HttpStatusCode.Accepted, resp.StatusCode);
            return (await resp.Content.ReadFromJsonAsync<MfaChallengeResponse>())!.MfaToken;
        }

        // Two challenges, every attempt from a new IP: the per-IP limiter never fires, the per-account one does.
        var first = await ChallengeAsync();
        var second = await ChallengeAsync();
        var client = factory.CreateClient();
        for (var i = 0; i < 3; i++)
        {
            var token = i % 2 == 0 ? first : second;
            var resp = await HardenedAuthApiFactory.SendAsync(client, HttpMethod.Post, "/v1/auth/login/totp", new { mfaToken = token, code = "000000" }, "127.0.0.1", ClientIp());
            Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
        }

        var limited = await HardenedAuthApiFactory.SendAsync(client, HttpMethod.Post, "/v1/auth/login/totp", new { mfaToken = second, code = "000000" }, "127.0.0.1", ClientIp());
        Assert.Equal(HttpStatusCode.TooManyRequests, limited.StatusCode);
        Assert.NotNull(limited.Headers.RetryAfter);
        Assert.Contains("Too many requests", await limited.Content.ReadAsStringAsync());

        // A bogus token is answered with the generic 401 without touching any account's budget.
        var bogus = await HardenedAuthApiFactory.SendAsync(client, HttpMethod.Post, "/v1/auth/login/totp", new { mfaToken = new string('A', 43), code = "000000" }, "127.0.0.1", ClientIp());
        Assert.Equal(HttpStatusCode.Unauthorized, bogus.StatusCode);
    }
}
