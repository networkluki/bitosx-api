using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using BitosX.Infrastructure.Email;
using Microsoft.Extensions.DependencyInjection;

namespace BitosX.Api.Tests;

public sealed class AuthEndpointsTests : IClassFixture<AuthApiFactory>, IAsyncLifetime
{
    private readonly AuthApiFactory _factory;

    public AuthEndpointsTests(AuthApiFactory factory) => _factory = factory;

    public async Task InitializeAsync() => await _factory.ResetDatabaseAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    private static string Email() => $"user-{Guid.NewGuid():N}@example.com";

    private async Task DispatchOnceAsync()
    {
        using var scope = _factory.Services.CreateScope();
        await scope.ServiceProvider.GetRequiredService<IEmailOutboxDispatcher>().ProcessDueOnceAsync();
    }

    [Fact]
    public async Task Register_NewEmail_Returns202_AccountHasNullPassword()
    {
        var client = _factory.CreateClient();
        var email = Email();

        var resp = await client.PostAsJsonAsync("/v1/auth/register", new { email });
        Assert.Equal(HttpStatusCode.Accepted, resp.StatusCode);

        var normalized = email.ToUpperInvariant();
        Assert.Equal(1L, await _factory.QueryScalarAsync<long>(
            "SELECT COUNT(*) FROM accounts WHERE normalized_email=@e AND password_hash IS NULL AND email_verified_at IS NULL", "@e", normalized));
    }

    [Fact]
    public async Task Register_WithExtraPasswordField_IsIgnored_NoPasswordStored()
    {
        var client = _factory.CreateClient();
        var email = Email();

        // Extra "password" field must be ignored by RegisterRequest{Email}.
        var resp = await client.PostAsJsonAsync("/v1/auth/register", new { email, password = "attacker-chosen-pw" });
        Assert.Equal(HttpStatusCode.Accepted, resp.StatusCode);
        Assert.Equal(1L, await _factory.QueryScalarAsync<long>(
            "SELECT COUNT(*) FROM accounts WHERE normalized_email=@e AND password_hash IS NULL", "@e", email.ToUpperInvariant()));
    }

    [Fact]
    public async Task Register_DuplicateEmail_ReturnsSameGeneric202()
    {
        var client = _factory.CreateClient();
        var email = Email();

        var first = await client.PostAsJsonAsync("/v1/auth/register", new { email });
        var second = await client.PostAsJsonAsync("/v1/auth/register", new { email });

        Assert.Equal(HttpStatusCode.Accepted, first.StatusCode);
        Assert.Equal(HttpStatusCode.Accepted, second.StatusCode);
        Assert.Equal(await first.Content.ReadAsStringAsync(), await second.Content.ReadAsStringAsync());
        // Only one account created.
        Assert.Equal(1L, await _factory.QueryScalarAsync<long>(
            "SELECT COUNT(*) FROM accounts WHERE normalized_email=@e", "@e", email.ToUpperInvariant()));
    }

    [Fact]
    public async Task Register_InvalidEmail_Returns400ProblemDetails()
    {
        var client = _factory.CreateClient();
        var resp = await client.PostAsJsonAsync("/v1/auth/register", new { email = "not-an-email" });
        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
        Assert.Contains("application/problem+json", resp.Content.Headers.ContentType?.MediaType);
    }

    [Fact]
    public async Task PreRegistrationTakeover_VictimChoosesPassword_AttackerCannot()
    {
        var client = _factory.CreateClient();
        var email = Email();

        // "attacker" starts registration (email only — cannot choose a password).
        await client.PostAsJsonAsync("/v1/auth/register", new { email });
        var normalized = email.ToUpperInvariant();
        Assert.Equal(1L, await _factory.QueryScalarAsync<long>(
            "SELECT COUNT(*) FROM accounts WHERE normalized_email=@e AND password_hash IS NULL", "@e", normalized));

        // Deliver the email (dispatcher -> capturing sender) and read the token.
        await DispatchOnceAsync();
        Assert.Single(_factory.Emails.Sent);
        var token = CapturingEmailSender.ExtractToken(_factory.Emails.Sent[0]);

        // "victim" verifies and chooses the password.
        var victimPassword = "victim-chosen-strong-pw";
        var verify = await client.PostAsJsonAsync("/v1/auth/verify-email", new { token, password = victimPassword });
        Assert.Equal(HttpStatusCode.OK, verify.StatusCode);

        // Account is now verified with the victim's password (never an attacker's).
        Assert.Equal(1L, await _factory.QueryScalarAsync<long>(
            "SELECT COUNT(*) FROM accounts WHERE normalized_email=@e AND email_verified_at IS NOT NULL AND password_hash IS NOT NULL", "@e", normalized));
    }

    [Fact]
    public async Task Verify_TooShortPassword_Returns400_ChallengeNotConsumed()
    {
        var client = _factory.CreateClient();
        var email = Email();
        await client.PostAsJsonAsync("/v1/auth/register", new { email });
        await DispatchOnceAsync();
        var token = CapturingEmailSender.ExtractToken(_factory.Emails.Sent[0]);

        var resp = await client.PostAsJsonAsync("/v1/auth/verify-email", new { token, password = "short" });
        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
        // Not verified.
        Assert.Equal(1L, await _factory.QueryScalarAsync<long>(
            "SELECT COUNT(*) FROM accounts WHERE normalized_email=@e AND email_verified_at IS NULL", "@e", email.ToUpperInvariant()));

        // And the challenge really is still usable: the same token with a valid password verifies the account.
        var retry = await client.PostAsJsonAsync("/v1/auth/verify-email", new { token, password = "a-valid-password-12" });
        Assert.Equal(HttpStatusCode.OK, retry.StatusCode);
        Assert.Equal(1L, await _factory.QueryScalarAsync<long>(
            "SELECT COUNT(*) FROM accounts WHERE normalized_email=@e AND email_verified_at IS NOT NULL", "@e", email.ToUpperInvariant()));
    }

    [Theory]
    [InlineData("{\"password\":\"a-valid-password-12\"}")]
    [InlineData("{\"token\":null,\"password\":\"a-valid-password-12\"}")]
    [InlineData("{\"token\":\"\",\"password\":\"a-valid-password-12\"}")]
    public async Task Verify_MissingOrNullToken_Returns400_Not500(string body)
    {
        var resp = await _factory.CreateClient().PostAsync("/v1/auth/verify-email", new StringContent(body, System.Text.Encoding.UTF8, "application/json"));
        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
        Assert.Contains("Invalid or expired verification token.", await resp.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Verify_BogusToken_Returns400Generic()
    {
        var client = _factory.CreateClient();
        var resp = await client.PostAsJsonAsync("/v1/auth/verify-email", new { token = "bogus-token-value", password = "a-valid-password-12" });
        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
    }

    [Fact]
    public async Task Resend_AlwaysReturns202()
    {
        var client = _factory.CreateClient();
        // Unknown email and a freshly-registered unverified email both → 202.
        Assert.Equal(HttpStatusCode.Accepted, (await client.PostAsJsonAsync("/v1/auth/resend-verification", new { email = "unknown@example.com" })).StatusCode);
        var email = Email();
        await client.PostAsJsonAsync("/v1/auth/register", new { email });
        Assert.Equal(HttpStatusCode.Accepted, (await client.PostAsJsonAsync("/v1/auth/resend-verification", new { email })).StatusCode);
    }

    [Fact]
    public async Task Register_StoresOnlyHmacVerifier_NotPlaintextToken()
    {
        var client = _factory.CreateClient();
        var email = Email();
        await client.PostAsJsonAsync("/v1/auth/register", new { email });
        await DispatchOnceAsync();
        var token = CapturingEmailSender.ExtractToken(_factory.Emails.Sent[0]);

        // The stored token_hash is exactly HMAC-SHA256(pepper, decoded 32 token bytes), computed independently here,
        // and it is neither the raw token bytes, nor their plain SHA-256, nor the token text.
        var raw = Convert.FromBase64String(token.Replace('-', '+').Replace('_', '/') + new string('=', (4 - token.Length % 4) % 4));
        Assert.Equal(32, raw.Length);
        var pepper = _factory.Services.GetRequiredService<BitosX.Application.Verification.EmailVerificationSecurityOptions>().Pepper;
        var expected = System.Security.Cryptography.HMACSHA256.HashData(System.Text.Encoding.UTF8.GetBytes(pepper), raw);

        var accountId = await _factory.QueryScalarAsync<Guid>("SELECT id FROM accounts WHERE normalized_email=@e", "@e", email.ToUpperInvariant());
        Assert.Equal(1L, await _factory.QueryScalarAsync<long>(
            "SELECT COUNT(*) FROM email_verification_challenges WHERE account_id = @a", "@a", accountId));
        Assert.Equal(1L, await _factory.QueryScalarAsync<long>(
            "SELECT COUNT(*) FROM email_verification_challenges WHERE token_hash = @t", "@t", expected));
        foreach (var forbidden in new[] { raw, System.Security.Cryptography.SHA256.HashData(raw), System.Text.Encoding.UTF8.GetBytes(token) })
        {
            Assert.Equal(0L, await _factory.QueryScalarAsync<long>(
                "SELECT COUNT(*) FROM email_verification_challenges WHERE token_hash = @t", "@t", forbidden));
        }
    }
}
