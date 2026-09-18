using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;

namespace BitosX.Api.Tests;

/// <summary>
/// End-to-end logout / logout-all tests. Both are authenticated: identity comes from the validated
/// JWT claims (sub/sid), never the body. Logout revokes only the caller's current session; logout-all
/// revokes every session. After revocation the access token's session is gone, so the same token is
/// rejected with a generic 401 (via the single SessionValidation seam).
/// </summary>
public sealed class LogoutEndpointTests : IClassFixture<LoginApiFactory>, IAsyncLifetime
{
    private const string ValidPassword = "Correct-Horse-Battery-Staple-1";

    private readonly LoginApiFactory _factory;

    public LogoutEndpointTests(LoginApiFactory factory) => _factory = factory;

    public async Task InitializeAsync() => await _factory.ResetDatabaseAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    private HttpClient AuthedClient(string accessToken)
    {
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        return client;
    }

    [Fact]
    public async Task Logout_Current_Returns204_RevokesOnlyCurrentSession()
    {
        var anon = _factory.CreateClient();
        var email = await _factory.CreateVerifiedAccountAsync(anon, ValidPassword);
        var sessionA = await LoginApiFactory.LoginAsync(anon, email, ValidPassword);
        var sessionB = await LoginApiFactory.LoginAsync(anon, email, ValidPassword);

        var resp = await AuthedClient(sessionA.AccessToken).PostAsync("/v1/auth/logout", null);
        Assert.Equal(HttpStatusCode.NoContent, resp.StatusCode);

        // Session A's refresh token is dead; session B is untouched.
        var refreshA = await anon.PostAsJsonAsync("/v1/auth/refresh", new { refreshToken = sessionA.RefreshToken });
        Assert.Equal(HttpStatusCode.Unauthorized, refreshA.StatusCode);

        var refreshB = await anon.PostAsJsonAsync("/v1/auth/refresh", new { refreshToken = sessionB.RefreshToken });
        Assert.Equal(HttpStatusCode.OK, refreshB.StatusCode);

        Assert.Equal(1L, await _factory.ActiveSessionCountAsync(email));
    }

    [Fact]
    public async Task Logout_ThenReuseSameAccessToken_Returns401()
    {
        var anon = _factory.CreateClient();
        var email = await _factory.CreateVerifiedAccountAsync(anon, ValidPassword);
        var session = await LoginApiFactory.LoginAsync(anon, email, ValidPassword);
        var client = AuthedClient(session.AccessToken);

        Assert.Equal(HttpStatusCode.NoContent, (await client.PostAsync("/v1/auth/logout", null)).StatusCode);

        // The session is revoked, so the same access token no longer authenticates.
        var again = await client.PostAsync("/v1/auth/logout", null);
        Assert.Equal(HttpStatusCode.Unauthorized, again.StatusCode);
    }

    [Fact]
    public async Task Logout_Unauthenticated_Returns401()
    {
        var client = _factory.CreateClient();
        var resp = await client.PostAsync("/v1/auth/logout", null);
        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    [Fact]
    public async Task Logout_GarbageBearerToken_Returns401()
    {
        var resp = await AuthedClient("not-a-valid-jwt").PostAsync("/v1/auth/logout", null);
        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    [Fact]
    public async Task LogoutAll_Returns204_RevokesAllSessions()
    {
        var anon = _factory.CreateClient();
        var email = await _factory.CreateVerifiedAccountAsync(anon, ValidPassword);
        var sessionA = await LoginApiFactory.LoginAsync(anon, email, ValidPassword);
        var sessionB = await LoginApiFactory.LoginAsync(anon, email, ValidPassword);
        Assert.Equal(2L, await _factory.ActiveSessionCountAsync(email));

        var resp = await AuthedClient(sessionA.AccessToken).PostAsync("/v1/auth/logout-all", null);
        Assert.Equal(HttpStatusCode.NoContent, resp.StatusCode);

        Assert.Equal(0L, await _factory.ActiveSessionCountAsync(email));
        Assert.Equal(HttpStatusCode.Unauthorized,
            (await anon.PostAsJsonAsync("/v1/auth/refresh", new { refreshToken = sessionA.RefreshToken })).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized,
            (await anon.PostAsJsonAsync("/v1/auth/refresh", new { refreshToken = sessionB.RefreshToken })).StatusCode);
    }

    [Fact]
    public async Task LogoutAll_Unauthenticated_Returns401()
    {
        var client = _factory.CreateClient();
        var resp = await client.PostAsync("/v1/auth/logout-all", null);
        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }
}
