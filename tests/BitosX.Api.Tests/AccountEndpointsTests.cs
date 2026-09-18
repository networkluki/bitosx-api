using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using BitosX.Contracts.Accounts;

namespace BitosX.Api.Tests;

/// <summary>
/// End-to-end tests for the protected account endpoints (/v1/account/me, /v1/account/sessions,
/// DELETE /v1/account/sessions/{id}). All require a valid bearer access token whose session is still
/// active (enforced by the single SessionValidation seam). Ownership is server-side; a non-owned or
/// nonexistent session is an indistinguishable 404. No response exposes secrets/verifiers/user-agent.
/// </summary>
public sealed class AccountEndpointsTests : IClassFixture<LoginApiFactory>, IAsyncLifetime
{
    private const string ValidPassword = "Correct-Horse-Battery-Staple-1";

    private readonly LoginApiFactory _factory;

    public AccountEndpointsTests(LoginApiFactory factory) => _factory = factory;

    public async Task InitializeAsync() => await _factory.ResetDatabaseAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    private HttpClient AuthedClient(string accessToken)
    {
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        return client;
    }

    // ---- GET /v1/account/me ----

    [Fact]
    public async Task Me_Authenticated_ReturnsOwnProfile()
    {
        var anon = _factory.CreateClient();
        var email = await _factory.CreateVerifiedAccountAsync(anon, ValidPassword);
        var login = await LoginApiFactory.LoginAsync(anon, email, ValidPassword);

        var resp = await AuthedClient(login.AccessToken).GetAsync("/v1/account/me");

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var me = await resp.Content.ReadFromJsonAsync<MeResponse>();
        Assert.NotNull(me);
        Assert.Equal(email, me!.Email);
        Assert.True(me.EmailVerified);
        Assert.NotEqual(Guid.Empty, me.AccountId);
        Assert.True(me.CreatedAt > DateTime.MinValue);
    }

    [Fact]
    public async Task Me_MissingBearer_Returns401()
    {
        var resp = await _factory.CreateClient().GetAsync("/v1/account/me");
        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    [Fact]
    public async Task Me_MalformedBearer_Returns401()
    {
        var resp = await AuthedClient("not-a-jwt").GetAsync("/v1/account/me");
        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    [Fact]
    public async Task Me_AfterLogoutAll_Returns401()
    {
        var anon = _factory.CreateClient();
        var email = await _factory.CreateVerifiedAccountAsync(anon, ValidPassword);
        var login = await LoginApiFactory.LoginAsync(anon, email, ValidPassword);
        var client = AuthedClient(login.AccessToken);

        (await client.PostAsync("/v1/auth/logout-all", null)).EnsureSuccessStatusCode();

        var resp = await client.GetAsync("/v1/account/me");
        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode); // session revoked → generic 401
    }

    [Fact]
    public async Task Me_ResponseHasNoSensitiveFields()
    {
        var anon = _factory.CreateClient();
        var email = await _factory.CreateVerifiedAccountAsync(anon, ValidPassword);
        var login = await LoginApiFactory.LoginAsync(anon, email, ValidPassword);

        var raw = await (await AuthedClient(login.AccessToken).GetAsync("/v1/account/me")).Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(raw);
        var props = doc.RootElement.EnumerateObject().Select(p => p.Name).ToArray();

        Assert.Equal(new[] { "accountId", "email", "emailVerified", "createdAt" }.OrderBy(n => n), props.OrderBy(n => n));
        foreach (var forbidden in new[] { "passwordHash", "password", "phoneE164", "disabledAt", "normalizedEmail", "token", "refreshToken" })
        {
            Assert.DoesNotContain(forbidden, props, StringComparer.OrdinalIgnoreCase);
        }
    }

    // ---- GET /v1/account/sessions ----

    [Fact]
    public async Task Sessions_Authenticated_ListsOnlyOwnUsableSessions_WithCurrentMarker()
    {
        var anon = _factory.CreateClient();
        var email = await _factory.CreateVerifiedAccountAsync(anon, ValidPassword);
        var sessionA = await LoginApiFactory.LoginAsync(anon, email, ValidPassword);
        await LoginApiFactory.LoginAsync(anon, email, ValidPassword); // second session

        var resp = await AuthedClient(sessionA.AccessToken).GetAsync("/v1/account/sessions");

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var sessions = await resp.Content.ReadFromJsonAsync<List<SessionResponse>>();
        Assert.NotNull(sessions);
        Assert.Equal(2, sessions!.Count);
        Assert.Single(sessions, s => s.Current); // exactly one current
        Assert.All(sessions, s => Assert.True(s.ExpiresAt > DateTime.UtcNow)); // effective expiry in the future
    }

    [Fact]
    public async Task Sessions_ExcludeAnotherAccountsSessions()
    {
        var anon = _factory.CreateClient();
        var mine = await _factory.CreateVerifiedAccountAsync(anon, ValidPassword);
        var myLogin = await LoginApiFactory.LoginAsync(anon, mine, ValidPassword);

        var other = await _factory.CreateVerifiedAccountAsync(anon, ValidPassword);
        await LoginApiFactory.LoginAsync(anon, other, ValidPassword);

        var sessions = await (await AuthedClient(myLogin.AccessToken).GetAsync("/v1/account/sessions"))
            .Content.ReadFromJsonAsync<List<SessionResponse>>();

        Assert.NotNull(sessions);
        Assert.Single(sessions!); // only my own session, never the other account's
    }

    [Fact]
    public async Task Sessions_ExcludesRevokedSessions()
    {
        var anon = _factory.CreateClient();
        var email = await _factory.CreateVerifiedAccountAsync(anon, ValidPassword);
        var sessionA = await LoginApiFactory.LoginAsync(anon, email, ValidPassword);
        var sessionB = await LoginApiFactory.LoginAsync(anon, email, ValidPassword);

        // Revoke session B via its own logout; A lists only usable sessions afterwards.
        (await AuthedClient(sessionB.AccessToken).PostAsync("/v1/auth/logout", null)).EnsureSuccessStatusCode();

        var sessions = await (await AuthedClient(sessionA.AccessToken).GetAsync("/v1/account/sessions"))
            .Content.ReadFromJsonAsync<List<SessionResponse>>();

        Assert.NotNull(sessions);
        Assert.Single(sessions!);
        Assert.True(sessions![0].Current); // the surviving one is A (the caller)
    }

    [Fact]
    public async Task Sessions_MissingBearer_Returns401()
    {
        var resp = await _factory.CreateClient().GetAsync("/v1/account/sessions");
        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    [Fact]
    public async Task Sessions_ResponseHasNoSensitiveFields()
    {
        var anon = _factory.CreateClient();
        var email = await _factory.CreateVerifiedAccountAsync(anon, ValidPassword);
        var login = await LoginApiFactory.LoginAsync(anon, email, ValidPassword);

        var raw = await (await AuthedClient(login.AccessToken).GetAsync("/v1/account/sessions")).Content.ReadAsStringAsync();
        using var doc = JsonDocument.Parse(raw);
        var props = doc.RootElement[0].EnumerateObject().Select(p => p.Name).ToArray();

        Assert.Equal(new[] { "id", "createdAt", "lastSeenAt", "expiresAt", "current" }.OrderBy(n => n), props.OrderBy(n => n));
        foreach (var forbidden in new[] { "userAgent", "accountId", "tokenHash", "verifier", "jti", "replacedByTokenId", "revokedAt" })
        {
            Assert.DoesNotContain(forbidden, props, StringComparer.OrdinalIgnoreCase);
        }
    }

    // ---- DELETE /v1/account/sessions/{id} ----

    [Fact]
    public async Task DeleteSession_OwnOtherSession_Returns204_AndRevokesIt()
    {
        var anon = _factory.CreateClient();
        var email = await _factory.CreateVerifiedAccountAsync(anon, ValidPassword);
        var sessionA = await LoginApiFactory.LoginAsync(anon, email, ValidPassword);
        var sessionB = await LoginApiFactory.LoginAsync(anon, email, ValidPassword);

        // Discover B's id from A's listing (the one not marked current).
        var sessions = await (await AuthedClient(sessionA.AccessToken).GetAsync("/v1/account/sessions"))
            .Content.ReadFromJsonAsync<List<SessionResponse>>();
        var targetB = sessions!.Single(s => !s.Current).Id;

        var del = await AuthedClient(sessionA.AccessToken).DeleteAsync($"/v1/account/sessions/{targetB}");
        Assert.Equal(HttpStatusCode.NoContent, del.StatusCode);

        // B's refresh token is now dead; A remains.
        Assert.Equal(HttpStatusCode.Unauthorized,
            (await anon.PostAsJsonAsync("/v1/auth/refresh", new { refreshToken = sessionB.RefreshToken })).StatusCode);
        Assert.Equal(1L, await _factory.ActiveSessionCountAsync(email));
    }

    [Fact]
    public async Task DeleteSession_CurrentSession_Returns204_ThenTokenRejected()
    {
        var anon = _factory.CreateClient();
        var email = await _factory.CreateVerifiedAccountAsync(anon, ValidPassword);
        var login = await LoginApiFactory.LoginAsync(anon, email, ValidPassword);
        var client = AuthedClient(login.AccessToken);

        var me = await (await client.GetAsync("/v1/account/sessions")).Content.ReadFromJsonAsync<List<SessionResponse>>();
        var currentId = me!.Single(s => s.Current).Id;

        var del = await client.DeleteAsync($"/v1/account/sessions/{currentId}");
        Assert.Equal(HttpStatusCode.NoContent, del.StatusCode); // deleting current session is allowed

        var after = await client.GetAsync("/v1/account/me");
        Assert.Equal(HttpStatusCode.Unauthorized, after.StatusCode); // session gone
    }

    [Fact]
    public async Task DeleteSession_NonexistentSession_Returns404()
    {
        var anon = _factory.CreateClient();
        var email = await _factory.CreateVerifiedAccountAsync(anon, ValidPassword);
        var login = await LoginApiFactory.LoginAsync(anon, email, ValidPassword);

        var del = await AuthedClient(login.AccessToken).DeleteAsync($"/v1/account/sessions/{Guid.NewGuid()}");
        Assert.Equal(HttpStatusCode.NotFound, del.StatusCode);
    }

    [Fact]
    public async Task DeleteSession_AnotherAccountsSession_Returns404_AndLeavesItUntouched()
    {
        var anon = _factory.CreateClient();
        var mine = await _factory.CreateVerifiedAccountAsync(anon, ValidPassword);
        var myLogin = await LoginApiFactory.LoginAsync(anon, mine, ValidPassword);

        var other = await _factory.CreateVerifiedAccountAsync(anon, ValidPassword);
        var otherLogin = await LoginApiFactory.LoginAsync(anon, other, ValidPassword);
        var otherSessions = await (await AuthedClient(otherLogin.AccessToken).GetAsync("/v1/account/sessions"))
            .Content.ReadFromJsonAsync<List<SessionResponse>>();
        var otherSessionId = otherSessions!.Single().Id;

        // Same 404 contract as a nonexistent id — no ownership/existence disclosure.
        var del = await AuthedClient(myLogin.AccessToken).DeleteAsync($"/v1/account/sessions/{otherSessionId}");
        Assert.Equal(HttpStatusCode.NotFound, del.StatusCode);

        // The other account's session is untouched (its refresh token still works).
        Assert.Equal(HttpStatusCode.OK,
            (await anon.PostAsJsonAsync("/v1/auth/refresh", new { refreshToken = otherLogin.RefreshToken })).StatusCode);
    }

    [Fact]
    public async Task DeleteSession_MalformedRouteId_Returns400Or404_NotServerError()
    {
        var anon = _factory.CreateClient();
        var email = await _factory.CreateVerifiedAccountAsync(anon, ValidPassword);
        var login = await LoginApiFactory.LoginAsync(anon, email, ValidPassword);

        // A non-GUID route value must never reach the service as a valid target.
        var del = await AuthedClient(login.AccessToken).DeleteAsync("/v1/account/sessions/not-a-guid");
        Assert.True(del.StatusCode is HttpStatusCode.BadRequest or HttpStatusCode.NotFound,
            $"expected 400 or 404, got {(int)del.StatusCode}");
    }

    [Fact]
    public async Task DeleteSession_Unauthenticated_Returns401()
    {
        var resp = await _factory.CreateClient().DeleteAsync($"/v1/account/sessions/{Guid.NewGuid()}");
        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }
}
