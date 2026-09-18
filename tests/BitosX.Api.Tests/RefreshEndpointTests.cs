using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using BitosX.Contracts.Accounts;

namespace BitosX.Api.Tests;

/// <summary>
/// End-to-end refresh endpoint tests. Refresh is unauthenticated (identity resolved from the token
/// by the store). Asserts rotation, strict session-scoped reuse revocation (no grace), and a single
/// generic 401 for every invalid-token case (anti-enumeration / no token-state disclosure).
/// </summary>
public sealed class RefreshEndpointTests : IClassFixture<LoginApiFactory>, IAsyncLifetime
{
    private const string ValidPassword = "Correct-Horse-Battery-Staple-1";

    private readonly LoginApiFactory _factory;

    public RefreshEndpointTests(LoginApiFactory factory) => _factory = factory;

    public async Task InitializeAsync() => await _factory.ResetDatabaseAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    private static string WellFormedButUnknownToken()
        => Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    [Fact]
    public async Task Refresh_ValidToken_Returns200_WithRotatedTokens()
    {
        var client = _factory.CreateClient();
        var email = await _factory.CreateVerifiedAccountAsync(client, ValidPassword);
        var login = await LoginApiFactory.LoginAsync(client, email, ValidPassword);

        var resp = await client.PostAsJsonAsync("/v1/auth/refresh", new { refreshToken = login.RefreshToken });

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var rotated = await resp.Content.ReadFromJsonAsync<TokenResponse>();
        Assert.NotNull(rotated);
        Assert.False(string.IsNullOrWhiteSpace(rotated!.AccessToken));
        Assert.False(string.IsNullOrWhiteSpace(rotated.RefreshToken));
        Assert.NotEqual(login.RefreshToken, rotated.RefreshToken); // rotated to a new opaque token
        Assert.Equal(1L, await _factory.ActiveSessionCountAsync(email));
    }

    [Fact]
    public async Task Refresh_ThenPresentOldToken_StrictReuse_RevokesSession_Returns401()
    {
        var client = _factory.CreateClient();
        var email = await _factory.CreateVerifiedAccountAsync(client, ValidPassword);
        var login = await LoginApiFactory.LoginAsync(client, email, ValidPassword);

        var first = await client.PostAsJsonAsync("/v1/auth/refresh", new { refreshToken = login.RefreshToken });
        first.EnsureSuccessStatusCode();
        var rotated = (await first.Content.ReadFromJsonAsync<TokenResponse>())!;

        // Re-presenting the now-consumed R0 is strict reuse: session-scoped revocation, no grace.
        var reuse = await client.PostAsJsonAsync("/v1/auth/refresh", new { refreshToken = login.RefreshToken });
        Assert.Equal(HttpStatusCode.Unauthorized, reuse.StatusCode);
        Assert.Equal(0L, await _factory.ActiveSessionCountAsync(email)); // whole session revoked

        // The successor R1 is now dead too (its session is revoked).
        var successor = await client.PostAsJsonAsync("/v1/auth/refresh", new { refreshToken = rotated.RefreshToken });
        Assert.Equal(HttpStatusCode.Unauthorized, successor.StatusCode);
    }

    [Fact]
    public async Task Refresh_ReuseRevocationIsSessionScoped_OtherSessionSurvives()
    {
        var client = _factory.CreateClient();
        var email = await _factory.CreateVerifiedAccountAsync(client, ValidPassword);
        var sessionA = await LoginApiFactory.LoginAsync(client, email, ValidPassword);
        var sessionB = await LoginApiFactory.LoginAsync(client, email, ValidPassword);
        Assert.Equal(2L, await _factory.ActiveSessionCountAsync(email));

        // Rotate + reuse on session A → A revoked.
        (await client.PostAsJsonAsync("/v1/auth/refresh", new { refreshToken = sessionA.RefreshToken })).EnsureSuccessStatusCode();
        var reuseA = await client.PostAsJsonAsync("/v1/auth/refresh", new { refreshToken = sessionA.RefreshToken });
        Assert.Equal(HttpStatusCode.Unauthorized, reuseA.StatusCode);

        // Session B is untouched.
        var refreshB = await client.PostAsJsonAsync("/v1/auth/refresh", new { refreshToken = sessionB.RefreshToken });
        Assert.Equal(HttpStatusCode.OK, refreshB.StatusCode);
        Assert.Equal(1L, await _factory.ActiveSessionCountAsync(email));
    }

    [Fact]
    public async Task Refresh_UnknownWellFormedToken_Returns401()
    {
        var client = _factory.CreateClient();
        var resp = await client.PostAsJsonAsync("/v1/auth/refresh", new { refreshToken = WellFormedButUnknownToken() });
        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    [Fact]
    public async Task Refresh_MalformedToken_WrongLength_Returns401()
    {
        var client = _factory.CreateClient();
        var resp = await client.PostAsJsonAsync("/v1/auth/refresh", new { refreshToken = "too-short" });
        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    [Fact]
    public async Task Refresh_MalformedJson_Returns400()
    {
        var client = _factory.CreateClient();
        using var content = new StringContent("{ nope ", Encoding.UTF8, "application/json");
        var resp = await client.PostAsync("/v1/auth/refresh", content);
        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
    }

    [Fact]
    public async Task Refresh_BodyOver4KiB_Returns413()
    {
        var client = _factory.CreateClient();
        var resp = await client.PostAsJsonAsync("/v1/auth/refresh", new { refreshToken = new string('x', 5000) });
        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, resp.StatusCode);
    }

    [Fact]
    public async Task Refresh_UnknownAndMalformed_ProduceIdenticalGenericBody()
    {
        var client = _factory.CreateClient();
        var unknown = await client.PostAsJsonAsync("/v1/auth/refresh", new { refreshToken = WellFormedButUnknownToken() });
        var malformed = await client.PostAsJsonAsync("/v1/auth/refresh", new { refreshToken = "too-short" });

        Assert.Equal(HttpStatusCode.Unauthorized, unknown.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, malformed.StatusCode);
        using var u = JsonDocument.Parse(await unknown.Content.ReadAsStringAsync());
        using var m = JsonDocument.Parse(await malformed.Content.ReadAsStringAsync());
        Assert.Equal(u.RootElement.GetProperty("title").GetString(), m.RootElement.GetProperty("title").GetString());
        Assert.Equal(u.RootElement.GetProperty("detail").GetString(), m.RootElement.GetProperty("detail").GetString());
    }
}
