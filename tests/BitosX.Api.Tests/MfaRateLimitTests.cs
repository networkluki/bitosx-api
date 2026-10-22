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
