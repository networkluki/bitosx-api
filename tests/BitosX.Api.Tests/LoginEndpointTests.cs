using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using BitosX.Contracts.Accounts;

namespace BitosX.Api.Tests;

/// <summary>
/// End-to-end login endpoint tests (register → verify → login) against bitosx_test with the Login
/// capability enabled. Asserts the token pair on success, a single generic 401 for every credential
/// failure (anti-enumeration), transport-level 400/413, and that no plaintext password is stored.
/// </summary>
public sealed class LoginEndpointTests : IClassFixture<LoginApiFactory>, IAsyncLifetime
{
    private const string ValidPassword = "Correct-Horse-Battery-Staple-1";

    private readonly LoginApiFactory _factory;

    public LoginEndpointTests(LoginApiFactory factory) => _factory = factory;

    public async Task InitializeAsync() => await _factory.ResetDatabaseAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    private static string Normalized(string email) => email.ToUpperInvariant();

    [Fact]
    public async Task Login_ValidCredentials_Returns200_WithTokens_AndCreatesSession()
    {
        var client = _factory.CreateClient();
        var email = await _factory.CreateVerifiedAccountAsync(client, ValidPassword);

        var resp = await client.PostAsJsonAsync("/v1/auth/login", new { email, password = ValidPassword });

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var body = await resp.Content.ReadFromJsonAsync<TokenResponse>();
        Assert.NotNull(body);
        Assert.False(string.IsNullOrWhiteSpace(body!.AccessToken));
        Assert.Equal(3, body.AccessToken.Split('.').Length);           // header.payload.signature
        Assert.False(string.IsNullOrWhiteSpace(body.RefreshToken));
        Assert.Equal("Bearer", body.TokenType);
        Assert.True(body.AccessTokenExpiresAt > DateTime.UtcNow);
        Assert.True(body.RefreshTokenExpiresAt > body.AccessTokenExpiresAt);

        Assert.Equal(1L, await _factory.QueryScalarAsync<long>(
            "SELECT COUNT(*) FROM sessions s JOIN accounts a ON a.id=s.account_id WHERE a.normalized_email=@e AND s.revoked_at IS NULL",
            "@e", Normalized(email)));
    }

    [Fact]
    public async Task Login_MixedCaseEmail_NormalizesAndSucceeds()
    {
        var client = _factory.CreateClient();
        var email = await _factory.CreateVerifiedAccountAsync(client, ValidPassword);

        // Case-folding is the normalization guarantee; surrounding whitespace is rejected as invalid
        // format (EmailAddressValidator) by design, so it must not be sent here.
        var resp = await client.PostAsJsonAsync("/v1/auth/login", new { email = email.ToUpperInvariant(), password = ValidPassword });

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    [Fact]
    public async Task Login_EmailWithSurroundingWhitespace_Returns401()
    {
        var client = _factory.CreateClient();
        var email = await _factory.CreateVerifiedAccountAsync(client, ValidPassword);

        // Whitespace is rejected by the format validator (fail closed) — same generic 401, no leak.
        var resp = await client.PostAsJsonAsync("/v1/auth/login", new { email = "  " + email + "  ", password = ValidPassword });

        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    [Fact]
    public async Task Login_UnknownEmail_Returns401()
    {
        var client = _factory.CreateClient();
        var resp = await client.PostAsJsonAsync("/v1/auth/login", new { email = $"nobody-{Guid.NewGuid():N}@example.com", password = ValidPassword });
        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    [Fact]
    public async Task Login_WrongPassword_Returns401()
    {
        var client = _factory.CreateClient();
        var email = await _factory.CreateVerifiedAccountAsync(client, ValidPassword);

        var resp = await client.PostAsJsonAsync("/v1/auth/login", new { email, password = "Wrong-Password-123456" });
        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }

    [Fact]
    public async Task Login_UnverifiedAccount_Returns401_NoSession()
    {
        var client = _factory.CreateClient();
        var email = $"unverified-{Guid.NewGuid():N}@example.com";
        (await client.PostAsJsonAsync("/v1/auth/register", new { email })).EnsureSuccessStatusCode();

        var resp = await client.PostAsJsonAsync("/v1/auth/login", new { email, password = ValidPassword });

        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
        Assert.Equal(0L, await _factory.QueryScalarAsync<long>(
            "SELECT COUNT(*) FROM sessions s JOIN accounts a ON a.id=s.account_id WHERE a.normalized_email=@e",
            "@e", Normalized(email)));
    }

    [Fact]
    public async Task Login_UnknownEmail_And_WrongPassword_ProduceIdenticalGenericBody()
    {
        var client = _factory.CreateClient();
        var email = await _factory.CreateVerifiedAccountAsync(client, ValidPassword);

        var unknown = await client.PostAsJsonAsync("/v1/auth/login", new { email = $"nobody-{Guid.NewGuid():N}@example.com", password = ValidPassword });
        var wrong = await client.PostAsJsonAsync("/v1/auth/login", new { email, password = "Wrong-Password-123456" });

        Assert.Equal(HttpStatusCode.Unauthorized, unknown.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, wrong.StatusCode);

        // The credential-relevant content must be identical (anti-enumeration). Only the per-request
        // ProblemDetails traceId legitimately differs, so compare title + detail, not the raw body.
        using var u = JsonDocument.Parse(await unknown.Content.ReadAsStringAsync());
        using var w = JsonDocument.Parse(await wrong.Content.ReadAsStringAsync());
        Assert.Equal(u.RootElement.GetProperty("title").GetString(), w.RootElement.GetProperty("title").GetString());
        Assert.Equal(u.RootElement.GetProperty("detail").GetString(), w.RootElement.GetProperty("detail").GetString());
        Assert.Equal("Invalid email or password.", u.RootElement.GetProperty("detail").GetString());
    }

    [Fact]
    public async Task Login_MalformedJson_Returns400()
    {
        var client = _factory.CreateClient();
        using var content = new StringContent("{ not valid json ", Encoding.UTF8, "application/json");
        var resp = await client.PostAsync("/v1/auth/login", content);
        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
    }

    [Fact]
    public async Task Login_BodyOver4KiB_Returns413()
    {
        var client = _factory.CreateClient();
        var hugePassword = new string('x', 5000); // body > 4 KiB
        var resp = await client.PostAsJsonAsync("/v1/auth/login", new { email = "a@example.com", password = hugePassword });
        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, resp.StatusCode);
    }

    [Fact]
    public async Task Login_OversizedPasswordWithinBodyLimit_Returns401_NoSession()
    {
        var client = _factory.CreateClient();
        var email = await _factory.CreateVerifiedAccountAsync(client, ValidPassword);
        var tooLongPassword = new string('y', 200); // > policy max (128), body still < 4 KiB

        var resp = await client.PostAsJsonAsync("/v1/auth/login", new { email, password = tooLongPassword });

        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
        Assert.Equal(0L, await _factory.QueryScalarAsync<long>(
            "SELECT COUNT(*) FROM sessions s JOIN accounts a ON a.id=s.account_id WHERE a.normalized_email=@e",
            "@e", Normalized(email)));
    }

    [Fact]
    public async Task Login_Success_StoresNoPlaintextPassword()
    {
        var client = _factory.CreateClient();
        var email = await _factory.CreateVerifiedAccountAsync(client, ValidPassword);
        (await client.PostAsJsonAsync("/v1/auth/login", new { email, password = ValidPassword })).EnsureSuccessStatusCode();

        var hash = await _factory.QueryScalarAsync<string>(
            "SELECT password_hash FROM accounts WHERE normalized_email=@e", "@e", Normalized(email));
        Assert.StartsWith("$argon2", hash);
        Assert.DoesNotContain(ValidPassword, hash, StringComparison.Ordinal);
    }
}
