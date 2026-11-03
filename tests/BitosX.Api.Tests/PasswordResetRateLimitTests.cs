using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using BitosX.Contracts.Accounts;

namespace BitosX.Api.Tests;

/// <summary>Hardened-mode limits on forgot/reset-password (per IP, per email) and account deletion (per account).</summary>
public sealed class PasswordResetRateLimitTests : IClassFixture<HardenedAuthApiFactory>, IAsyncLifetime
{
    private const string ValidPassword = "Correct-Horse-Battery-Staple-1";

    private readonly HardenedAuthApiFactory _factory;

    public PasswordResetRateLimitTests(HardenedAuthApiFactory factory) => _factory = factory;

    public async Task InitializeAsync() => await _factory.ResetDatabaseAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    private static int _ipCounter = 7_000;
    private static string ClientIp() { var n = Interlocked.Increment(ref _ipCounter); return $"10.{(n >> 16) & 0xff}.{(n >> 8) & 0xff}.{n & 0xff}"; }
    private static string Email() => $"u-{Guid.NewGuid():N}@example.com";

    private Task<HttpResponseMessage> ForgotAsync(string email, string xff)
        => HardenedAuthApiFactory.SendAsync(_factory.CreateClient(), HttpMethod.Post, "/v1/auth/forgot-password", new { email }, "127.0.0.1", xff);

    [Fact]
    public async Task ForgotPassword_PerIp_SixthRequestIsLimited_OtherIpUnaffected()
    {
        var ip = ClientIp();
        for (var i = 0; i < 5; i++)
        {
            Assert.Equal(HttpStatusCode.Accepted, (await ForgotAsync(Email(), ip)).StatusCode);
        }

        var limited = await ForgotAsync(Email(), ip);
        Assert.Equal(HttpStatusCode.TooManyRequests, limited.StatusCode);
        Assert.NotNull(limited.Headers.RetryAfter);
        Assert.Equal(HttpStatusCode.Accepted, (await ForgotAsync(Email(), ClientIp())).StatusCode);
    }

    [Fact]
    public async Task ForgotPassword_PerEmail_FourthRequestForSameAddressIsLimited_EvenAcrossIps()
    {
        var email = Email(); // unknown address: the limiter must behave identically for it
        for (var i = 0; i < 3; i++)
        {
            Assert.Equal(HttpStatusCode.Accepted, (await ForgotAsync(email, ClientIp())).StatusCode);
        }

        Assert.Equal(HttpStatusCode.TooManyRequests, (await ForgotAsync(email.ToUpperInvariant(), ClientIp())).StatusCode); // same normalized email
        Assert.Equal(HttpStatusCode.Accepted, (await ForgotAsync(Email(), ClientIp())).StatusCode);
    }

    [Fact]
    public async Task ResetPassword_PerIp_SharesTheForgotBucket()
    {
        var ip = ClientIp();
        var client = _factory.CreateClient();
        for (var i = 0; i < 5; i++)
        {
            var resp = await HardenedAuthApiFactory.SendAsync(client, HttpMethod.Post, "/v1/auth/reset-password", new { token = "bogus", password = ValidPassword }, "127.0.0.1", ip);
            Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
        }

        var limited = await HardenedAuthApiFactory.SendAsync(client, HttpMethod.Post, "/v1/auth/reset-password", new { token = "bogus", password = ValidPassword }, "127.0.0.1", ip);
        Assert.Equal(HttpStatusCode.TooManyRequests, limited.StatusCode);
    }

    [Fact]
    public async Task ForgotPassword_UnresolvableClientIp_Returns503()
    {
        // Loopback peer without a forwarded client address → no usable key → fail closed.
        var resp = await HardenedAuthApiFactory.SendAsync(_factory.CreateClient(), HttpMethod.Post, "/v1/auth/forgot-password", new { email = Email() }, "127.0.0.1", null);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, resp.StatusCode);
    }

    [Fact]
    public async Task DeleteAccount_PerAccount_SixthAttemptIsLimited()
    {
        var email = await _factory.CreateVerifiedAccountAsync(ValidPassword);
        var loginResp = await HardenedAuthApiFactory.SendAsync(_factory.CreateClient(), HttpMethod.Post, "/v1/auth/login", new { email, password = ValidPassword }, "127.0.0.1", ClientIp());
        loginResp.EnsureSuccessStatusCode();
        var tokens = (await loginResp.Content.ReadFromJsonAsync<TokenResponse>())!;
        var authed = _factory.CreateClient();
        authed.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tokens.AccessToken);

        for (var i = 0; i < 5; i++)
        {
            var resp = await HardenedAuthApiFactory.SendAsync(authed, HttpMethod.Post, "/v1/account/delete", new { password = "Wrong-Password-Entirely-9" }, "127.0.0.1", ClientIp());
            Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
        }

        var limited = await HardenedAuthApiFactory.SendAsync(authed, HttpMethod.Post, "/v1/account/delete", new { password = ValidPassword }, "127.0.0.1", ClientIp());
        Assert.Equal(HttpStatusCode.TooManyRequests, limited.StatusCode);
        Assert.Equal(1L, await _factory.QueryScalarAsync<long>("SELECT COUNT(*) FROM accounts WHERE normalized_email=@e", "@e", email.ToUpperInvariant()));
    }

    [Fact]
    public async Task ChangePassword_PerAccount_SixthAttemptIsLimited()
    {
        var email = await _factory.CreateVerifiedAccountAsync(ValidPassword);
        var loginResp = await HardenedAuthApiFactory.SendAsync(_factory.CreateClient(), HttpMethod.Post, "/v1/auth/login", new { email, password = ValidPassword }, "127.0.0.1", ClientIp());
        loginResp.EnsureSuccessStatusCode();
        var tokens = (await loginResp.Content.ReadFromJsonAsync<TokenResponse>())!;
        var authed = _factory.CreateClient();
        authed.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tokens.AccessToken);

        for (var i = 0; i < 5; i++)
        {
            var resp = await HardenedAuthApiFactory.SendAsync(authed, HttpMethod.Post, "/v1/account/password",
                new { currentPassword = "Wrong-Password-Entirely-9", newPassword = "Brand-New-Account-Password-2" }, "127.0.0.1", ClientIp());
            Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
        }

        var limited = await HardenedAuthApiFactory.SendAsync(authed, HttpMethod.Post, "/v1/account/password",
            new { currentPassword = ValidPassword, newPassword = "Brand-New-Account-Password-2" }, "127.0.0.1", ClientIp());
        Assert.Equal(HttpStatusCode.TooManyRequests, limited.StatusCode);
        Assert.NotNull(limited.Headers.RetryAfter);

        // The limit is per account: another account is unaffected.
        var otherEmail = await _factory.CreateVerifiedAccountAsync(ValidPassword);
        var otherLogin = await HardenedAuthApiFactory.SendAsync(_factory.CreateClient(), HttpMethod.Post, "/v1/auth/login", new { email = otherEmail, password = ValidPassword }, "127.0.0.1", ClientIp());
        var otherTokens = (await otherLogin.Content.ReadFromJsonAsync<TokenResponse>())!;
        var otherClient = _factory.CreateClient();
        otherClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", otherTokens.AccessToken);
        var ok = await HardenedAuthApiFactory.SendAsync(otherClient, HttpMethod.Post, "/v1/account/password",
            new { currentPassword = "Wrong-Password-Entirely-9", newPassword = "Brand-New-Account-Password-2" }, "127.0.0.1", ClientIp());
        Assert.Equal(HttpStatusCode.Forbidden, ok.StatusCode);
    }
}
