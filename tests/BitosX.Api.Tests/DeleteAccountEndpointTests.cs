using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;

namespace BitosX.Api.Tests;

/// <summary>
/// End-to-end account deletion (<c>POST /v1/account/delete</c>): password-confirmed, authenticated, and
/// removes the account with everything it owns, including the stored vault envelope.
/// </summary>
public sealed class DeleteAccountEndpointTests : IClassFixture<LoginApiFactory>, IAsyncLifetime
{
    private const string Password = "Correct-Horse-Battery-Staple-1";

    private readonly LoginApiFactory _factory;

    public DeleteAccountEndpointTests(LoginApiFactory factory) => _factory = factory;

    public async Task InitializeAsync() => await _factory.ResetDatabaseAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    private HttpClient AuthedClient(string accessToken)
    {
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        return client;
    }

    private static async Task UploadEnvelopeAsync(HttpClient authed)
    {
        var envelope = "{\"version\":1,\"kdf\":\"argon2id\",\"ciphertext\":\"AAAA\"}"u8.ToArray();
        var resp = await authed.PutAsJsonAsync("/v1/sync/envelope", new { baseRevision = 0, envelope = Convert.ToBase64String(envelope) });
        resp.EnsureSuccessStatusCode();
    }

    [Fact]
    public async Task Delete_CorrectPassword_Returns204_RemovesAccountSessionsAndVault()
    {
        var anon = _factory.CreateClient();
        var email = await _factory.CreateVerifiedAccountAsync(anon, Password);
        var login = await LoginApiFactory.LoginAsync(anon, email, Password);
        var other = await LoginApiFactory.LoginAsync(anon, email, Password);
        var authed = AuthedClient(login.AccessToken);
        await UploadEnvelopeAsync(authed);
        var normalized = email.ToUpperInvariant();
        Assert.Equal(1L, await _factory.QueryScalarAsync<long>("SELECT COUNT(*) FROM vault_blobs v JOIN accounts a ON a.id=v.account_id WHERE a.normalized_email=@e", "@e", normalized));

        var resp = await authed.PostAsJsonAsync("/v1/account/delete", new { password = Password });

        Assert.Equal(HttpStatusCode.NoContent, resp.StatusCode);
        Assert.Equal(0L, await _factory.QueryScalarAsync<long>("SELECT COUNT(*) FROM accounts WHERE normalized_email=@e", "@e", normalized));
        Assert.Equal(0L, await _factory.QueryScalarAsync<long>("SELECT COUNT(*) FROM vault_blobs", "@e", normalized));
        Assert.Equal(0L, await _factory.QueryScalarAsync<long>("SELECT COUNT(*) FROM sessions", "@e", normalized));
        Assert.Equal(0L, await _factory.QueryScalarAsync<long>("SELECT COUNT(*) FROM refresh_tokens", "@e", normalized));
        Assert.Equal(0L, await _factory.QueryScalarAsync<long>("SELECT COUNT(*) FROM email_verification_challenges", "@e", normalized));
        Assert.Equal(0L, await _factory.QueryScalarAsync<long>("SELECT COUNT(*) FROM email_outbox", "@e", normalized));

        // Nothing about the account works any more.
        Assert.Equal(HttpStatusCode.Unauthorized, (await authed.GetAsync("/v1/account/me")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await AuthedClient(other.AccessToken).GetAsync("/v1/account/me")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await anon.PostAsJsonAsync("/v1/auth/refresh", new { refreshToken = other.RefreshToken })).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await anon.PostAsJsonAsync("/v1/auth/login", new { email, password = Password })).StatusCode);

        // The address can register again from scratch.
        Assert.Equal(HttpStatusCode.Accepted, (await anon.PostAsJsonAsync("/v1/auth/register", new { email })).StatusCode);
        Assert.Equal(1L, await _factory.QueryScalarAsync<long>("SELECT COUNT(*) FROM accounts WHERE normalized_email=@e AND password_hash IS NULL", "@e", normalized));
    }

    [Fact]
    public async Task Delete_WrongPassword_Returns403_NothingDeleted_SessionStaysValid()
    {
        var anon = _factory.CreateClient();
        var email = await _factory.CreateVerifiedAccountAsync(anon, Password);
        var login = await LoginApiFactory.LoginAsync(anon, email, Password);
        var authed = AuthedClient(login.AccessToken);
        await UploadEnvelopeAsync(authed);

        var resp = await authed.PostAsJsonAsync("/v1/account/delete", new { password = "Wrong-Password-Entirely-9" });

        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
        Assert.Contains("application/problem+json", resp.Content.Headers.ContentType?.MediaType);
        Assert.Equal(1L, await _factory.QueryScalarAsync<long>("SELECT COUNT(*) FROM accounts WHERE normalized_email=@e", "@e", email.ToUpperInvariant()));
        Assert.Equal(1L, await _factory.QueryScalarAsync<long>("SELECT COUNT(*) FROM vault_blobs v JOIN accounts a ON a.id=v.account_id WHERE a.normalized_email=@e", "@e", email.ToUpperInvariant()));
        Assert.Equal(HttpStatusCode.OK, (await authed.GetAsync("/v1/account/me")).StatusCode); // 403 did not kill the session
    }

    [Fact]
    public async Task Delete_EmptyPassword_Returns403()
    {
        var anon = _factory.CreateClient();
        var email = await _factory.CreateVerifiedAccountAsync(anon, Password);
        var login = await LoginApiFactory.LoginAsync(anon, email, Password);

        var resp = await AuthedClient(login.AccessToken).PostAsJsonAsync("/v1/account/delete", new { password = "" });
        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
    }

    [Fact]
    public async Task Delete_MissingOrInvalidBearer_Returns401_NothingDeleted()
    {
        var anon = _factory.CreateClient();
        var email = await _factory.CreateVerifiedAccountAsync(anon, Password);

        Assert.Equal(HttpStatusCode.Unauthorized, (await anon.PostAsJsonAsync("/v1/account/delete", new { password = Password })).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await AuthedClient("not-a-jwt").PostAsJsonAsync("/v1/account/delete", new { password = Password })).StatusCode);
        Assert.Equal(1L, await _factory.QueryScalarAsync<long>("SELECT COUNT(*) FROM accounts WHERE normalized_email=@e", "@e", email.ToUpperInvariant()));
    }

    [Fact]
    public async Task Delete_OversizedBody_Returns413()
    {
        var anon = _factory.CreateClient();
        var email = await _factory.CreateVerifiedAccountAsync(anon, Password);
        var login = await LoginApiFactory.LoginAsync(anon, email, Password);

        using var request = new HttpRequestMessage(HttpMethod.Post, "/v1/account/delete")
        {
            Content = JsonContent.Create(new { password = Password, padding = new string('x', 5000) }),
        };
        var resp = await AuthedClient(login.AccessToken).SendAsync(request);
        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, resp.StatusCode);
    }

    [Fact]
    public async Task Delete_ExtraAccountIdInBody_IsIgnored_OnlyCallerDeleted()
    {
        var anon = _factory.CreateClient();
        var victim = await _factory.CreateVerifiedAccountAsync(anon, Password);
        var attacker = await _factory.CreateVerifiedAccountAsync(anon, Password);
        var victimId = await _factory.QueryScalarAsync<Guid>("SELECT id FROM accounts WHERE normalized_email=@e", "@e", victim.ToUpperInvariant());
        var login = await LoginApiFactory.LoginAsync(anon, attacker, Password);

        var resp = await AuthedClient(login.AccessToken).PostAsJsonAsync("/v1/account/delete", new { password = Password, accountId = victimId });

        Assert.Equal(HttpStatusCode.NoContent, resp.StatusCode);
        Assert.Equal(1L, await _factory.QueryScalarAsync<long>("SELECT COUNT(*) FROM accounts WHERE normalized_email=@e", "@e", victim.ToUpperInvariant()));
        Assert.Equal(0L, await _factory.QueryScalarAsync<long>("SELECT COUNT(*) FROM accounts WHERE normalized_email=@e", "@e", attacker.ToUpperInvariant()));
    }
}
