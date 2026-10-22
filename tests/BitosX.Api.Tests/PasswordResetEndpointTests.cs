using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using BitosX.Infrastructure.Email;
using Microsoft.Extensions.DependencyInjection;

namespace BitosX.Api.Tests;

/// <summary>
/// End-to-end password reset through the real endpoints: generic forgot-password responses, the reset
/// email, replacing the password, revoking every session, single use, purpose binding and policy checks.
/// </summary>
public sealed class PasswordResetEndpointTests : IClassFixture<LoginApiFactory>, IAsyncLifetime
{
    private const string OldPassword = "Correct-Horse-Battery-Staple-1";
    private const string NewPassword = "Another-Strong-Password-22";

    private readonly LoginApiFactory _factory;

    public PasswordResetEndpointTests(LoginApiFactory factory) => _factory = factory;

    public async Task InitializeAsync() => await _factory.ResetDatabaseAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    private async Task DispatchOnceAsync()
    {
        using var scope = _factory.Services.CreateScope();
        await scope.ServiceProvider.GetRequiredService<IEmailOutboxDispatcher>().ProcessDueOnceAsync();
    }

    private async Task<string> RequestResetTokenAsync(HttpClient client, string email)
    {
        var sentBefore = _factory.Emails.Sent.Count;
        var resp = await client.PostAsJsonAsync("/v1/auth/forgot-password", new { email });
        Assert.Equal(HttpStatusCode.Accepted, resp.StatusCode);
        await DispatchOnceAsync();
        Assert.Equal(sentBefore + 1, _factory.Emails.Sent.Count);
        var mail = _factory.Emails.Sent[^1];
        Assert.Contains("/reset-password#token=", mail.TextBody);
        Assert.Equal(email, mail.ToAddress);
        return CapturingEmailSender.ExtractToken(mail);
    }

    private HttpClient AuthedClient(string accessToken)
    {
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        return client;
    }

    [Fact]
    public async Task ForgotPassword_UnknownAndKnownEmail_IdenticalGeneric202_NoMailForUnknown()
    {
        var client = _factory.CreateClient();
        var known = await _factory.CreateVerifiedAccountAsync(client, OldPassword);
        _factory.Emails.Sent.Clear();

        var unknown = await client.PostAsJsonAsync("/v1/auth/forgot-password", new { email = $"nobody-{Guid.NewGuid():N}@example.com" });
        var existing = await client.PostAsJsonAsync("/v1/auth/forgot-password", new { email = known });

        Assert.Equal(HttpStatusCode.Accepted, unknown.StatusCode);
        Assert.Equal(HttpStatusCode.Accepted, existing.StatusCode);
        Assert.Equal(await unknown.Content.ReadAsStringAsync(), await existing.Content.ReadAsStringAsync());

        await DispatchOnceAsync();
        Assert.Single(_factory.Emails.Sent); // only the verified account got a reset mail
        Assert.Equal(known, _factory.Emails.Sent[0].ToAddress);
        Assert.Contains("password", _factory.Emails.Sent[0].Subject, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ForgotPassword_UnverifiedAccount_Generic202_NoMail()
    {
        var client = _factory.CreateClient();
        var email = $"user-{Guid.NewGuid():N}@example.com";
        (await client.PostAsJsonAsync("/v1/auth/register", new { email })).EnsureSuccessStatusCode();
        await DispatchOnceAsync(); // delivers the verification mail
        _factory.Emails.Sent.Clear();

        var resp = await client.PostAsJsonAsync("/v1/auth/forgot-password", new { email });
        Assert.Equal(HttpStatusCode.Accepted, resp.StatusCode);
        await DispatchOnceAsync();
        Assert.Empty(_factory.Emails.Sent);
        Assert.Equal(0L, await _factory.QueryScalarAsync<long>(
            "SELECT COUNT(*) FROM email_verification_challenges c JOIN accounts a ON a.id=c.account_id WHERE a.normalized_email=@e AND c.purpose='password_reset'", "@e", email.ToUpperInvariant()));
    }

    [Fact]
    public async Task ForgotPassword_InvalidEmail_StillGeneric202()
    {
        var resp = await _factory.CreateClient().PostAsJsonAsync("/v1/auth/forgot-password", new { email = "not-an-email" });
        Assert.Equal(HttpStatusCode.Accepted, resp.StatusCode);
    }

    [Fact]
    public async Task ResetPassword_FullFlow_NewPasswordWorks_OldFails_AllSessionsRevoked_TokenSingleUse()
    {
        var client = _factory.CreateClient();
        var email = await _factory.CreateVerifiedAccountAsync(client, OldPassword);
        var session1 = await LoginApiFactory.LoginAsync(client, email, OldPassword);
        var session2 = await LoginApiFactory.LoginAsync(client, email, OldPassword);
        Assert.Equal(2L, await _factory.ActiveSessionCountAsync(email));

        var token = await RequestResetTokenAsync(client, email);

        var reset = await client.PostAsJsonAsync("/v1/auth/reset-password", new { token, password = NewPassword });
        Assert.Equal(HttpStatusCode.OK, reset.StatusCode);
        var body = await reset.Content.ReadAsStringAsync();
        Assert.DoesNotContain(token, body);

        // Every session is gone: access tokens no longer authenticate, refresh tokens are dead.
        Assert.Equal(0L, await _factory.ActiveSessionCountAsync(email));
        Assert.Equal(HttpStatusCode.Unauthorized, (await AuthedClient(session1.AccessToken).GetAsync("/v1/account/me")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await AuthedClient(session2.AccessToken).GetAsync("/v1/account/me")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.PostAsJsonAsync("/v1/auth/refresh", new { refreshToken = session1.RefreshToken })).StatusCode);

        // Old password fails, new password works.
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.PostAsJsonAsync("/v1/auth/login", new { email, password = OldPassword })).StatusCode);
        var relogin = await LoginApiFactory.LoginAsync(client, email, NewPassword);
        Assert.Equal(HttpStatusCode.OK, (await AuthedClient(relogin.AccessToken).GetAsync("/v1/account/me")).StatusCode);

        // Single use.
        var again = await client.PostAsJsonAsync("/v1/auth/reset-password", new { token, password = "Yet-Another-Password-333" });
        Assert.Equal(HttpStatusCode.BadRequest, again.StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await client.PostAsJsonAsync("/v1/auth/login", new { email, password = NewPassword })).StatusCode);
    }

    [Fact]
    public async Task ResetPassword_SecondRequest_InvalidatesFirstLink()
    {
        var client = _factory.CreateClient();
        var email = await _factory.CreateVerifiedAccountAsync(client, OldPassword);

        var first = await RequestResetTokenAsync(client, email);
        // Force the second issue past the min re-issue interval without waiting.
        await _factory.ExecuteAsync(
            "UPDATE email_verification_challenges c JOIN accounts a ON a.id=c.account_id SET c.created_at = DATE_SUB(c.created_at, INTERVAL 10 MINUTE) WHERE a.normalized_email=@e AND c.purpose='password_reset'", "@e", email.ToUpperInvariant());
        var second = await RequestResetTokenAsync(client, email);
        Assert.NotEqual(first, second);

        Assert.Equal(HttpStatusCode.BadRequest, (await client.PostAsJsonAsync("/v1/auth/reset-password", new { token = first, password = NewPassword })).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await client.PostAsJsonAsync("/v1/auth/reset-password", new { token = second, password = NewPassword })).StatusCode);
    }

    [Fact]
    public async Task ResetPassword_TooShortPassword_Returns400_TokenStaysUsable()
    {
        var client = _factory.CreateClient();
        var email = await _factory.CreateVerifiedAccountAsync(client, OldPassword);
        var token = await RequestResetTokenAsync(client, email);

        var resp = await client.PostAsJsonAsync("/v1/auth/reset-password", new { token, password = "short" });
        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
        Assert.Contains("application/problem+json", resp.Content.Headers.ContentType?.MediaType);

        Assert.Equal(HttpStatusCode.OK, (await client.PostAsJsonAsync("/v1/auth/login", new { email, password = OldPassword })).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await client.PostAsJsonAsync("/v1/auth/reset-password", new { token, password = NewPassword })).StatusCode);
    }

    [Fact]
    public async Task ResetPassword_BogusOrMalformedToken_Returns400Generic()
    {
        var client = _factory.CreateClient();
        var bogus = await client.PostAsJsonAsync("/v1/auth/reset-password", new { token = "bogus-token-value", password = NewPassword });
        var malformed = await client.PostAsJsonAsync("/v1/auth/reset-password", new { token = "not base64url!!", password = NewPassword });
        Assert.Equal(HttpStatusCode.BadRequest, bogus.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, malformed.StatusCode);
        // Same generic ProblemDetails (ignoring the per-response traceId).
        using var b = System.Text.Json.JsonDocument.Parse(await bogus.Content.ReadAsStringAsync());
        using var m = System.Text.Json.JsonDocument.Parse(await malformed.Content.ReadAsStringAsync());
        Assert.Equal(b.RootElement.GetProperty("detail").GetString(), m.RootElement.GetProperty("detail").GetString());
        Assert.Equal("Invalid or expired password-reset token.", b.RootElement.GetProperty("detail").GetString());
    }

    [Fact]
    public async Task VerificationToken_CannotResetPassword_AndResetToken_CannotVerifyEmail()
    {
        var client = _factory.CreateClient();

        // A fresh verification token presented to reset-password: rejected, account stays unverified.
        var email = $"user-{Guid.NewGuid():N}@example.com";
        (await client.PostAsJsonAsync("/v1/auth/register", new { email })).EnsureSuccessStatusCode();
        await DispatchOnceAsync();
        var verifyToken = CapturingEmailSender.ExtractToken(_factory.Emails.Sent[^1]);
        Assert.Equal(HttpStatusCode.BadRequest, (await client.PostAsJsonAsync("/v1/auth/reset-password", new { token = verifyToken, password = NewPassword })).StatusCode);
        Assert.Equal(1L, await _factory.QueryScalarAsync<long>(
            "SELECT COUNT(*) FROM accounts WHERE normalized_email=@e AND password_hash IS NULL AND email_verified_at IS NULL", "@e", email.ToUpperInvariant()));

        // A reset token presented to verify-email: rejected, password unchanged.
        var verified = await _factory.CreateVerifiedAccountAsync(client, OldPassword);
        var resetToken = await RequestResetTokenAsync(client, verified);
        Assert.Equal(HttpStatusCode.BadRequest, (await client.PostAsJsonAsync("/v1/auth/verify-email", new { token = resetToken, password = NewPassword })).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await client.PostAsJsonAsync("/v1/auth/login", new { email = verified, password = OldPassword })).StatusCode);
    }

    [Fact]
    public async Task ForgotPassword_OversizedBody_Returns413()
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "/v1/auth/forgot-password")
        {
            Content = JsonContent.Create(new { email = "a@example.com", padding = new string('x', 5000) }),
        };
        var resp = await _factory.CreateClient().SendAsync(request);
        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, resp.StatusCode);
    }
}
