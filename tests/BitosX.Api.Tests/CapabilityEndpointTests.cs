using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;

namespace BitosX.Api.Tests;

/// <summary>Phase 1: capability-gated endpoint behavior (SMTP delivery disabled).</summary>
public sealed class CapabilityEndpointTests
{
    private static string Email() => $"user-{Guid.NewGuid():N}@example.com";

    // ---- EmailVerification enabled, EmailDelivery disabled, Email:HoldInOutbox (Testing only) ----

    [Fact]
    public async Task HoldInOutbox_RegisterAndForgotPassword_Return202_AndKeepTheMailQueued_NoDispatcher()
    {
        await using var factory = new CapabilityApiFactory(verification: true, holdInOutbox: true);
        await factory.ResetDatabaseAsync();
        var client = factory.CreateClient();
        var email = Email();

        var register = await client.PostAsJsonAsync("/v1/auth/register", new { email });
        Assert.Equal(HttpStatusCode.Accepted, register.StatusCode);
        Assert.Equal(1L, await factory.CountAsync("SELECT COUNT(*) FROM accounts"));
        Assert.Equal(1L, await factory.CountAsync(
            "SELECT COUNT(*) FROM email_outbox WHERE message_type = 'email_verification' AND sent_at IS NULL AND failed_at IS NULL AND payload_ciphertext IS NOT NULL"));

        var resend = await client.PostAsJsonAsync("/v1/auth/resend-verification", new { email });
        Assert.Equal(HttpStatusCode.Accepted, resend.StatusCode);

        // Nothing can deliver: no SMTP sender and no background dispatcher exist.
        Assert.Null(factory.Services.GetService(typeof(BitosX.Application.Email.IEmailSender)));
        Assert.DoesNotContain(factory.Services.GetServices<Microsoft.Extensions.Hosting.IHostedService>(),
            s => s is BitosX.Infrastructure.Email.EmailOutboxBackgroundService);

        var forgot = await client.PostAsJsonAsync("/v1/auth/forgot-password", new { email = Email() });
        Assert.Equal(HttpStatusCode.Accepted, forgot.StatusCode); // unknown address: same generic answer, nothing queued
        Assert.Equal(0L, await factory.CountAsync("SELECT COUNT(*) FROM email_outbox WHERE message_type = 'password_reset'"));
        Assert.Equal(0L, await factory.CountAsync("SELECT COUNT(*) FROM email_outbox WHERE sent_at IS NOT NULL OR failed_at IS NOT NULL"));
    }

    [Fact]
    public async Task Register_WhenDeliveryDisabled_Returns503_AndCreatesNothing()
    {
        await using var factory = new CapabilityApiFactory(verification: true);
        await factory.ResetDatabaseAsync();
        var client = factory.CreateClient();

        var resp = await client.PostAsJsonAsync("/v1/auth/register", new { email = Email() });

        Assert.Equal(HttpStatusCode.ServiceUnavailable, resp.StatusCode);
        Assert.Equal("application/problem+json", resp.Content.Headers.ContentType?.MediaType);
        // No account/challenge/outbox created by the 503.
        Assert.Equal(0L, await factory.CountAsync("SELECT COUNT(*) FROM accounts"));
        Assert.Equal(0L, await factory.CountAsync("SELECT COUNT(*) FROM email_verification_challenges"));
        Assert.Equal(0L, await factory.CountAsync("SELECT COUNT(*) FROM email_outbox"));
    }

    [Fact]
    public async Task ForgotPassword_WhenDeliveryDisabled_Returns503_AndCreatesNothing()
    {
        await using var factory = new CapabilityApiFactory(verification: true);
        await factory.ResetDatabaseAsync();
        var client = factory.CreateClient();

        var resp = await client.PostAsJsonAsync("/v1/auth/forgot-password", new { email = Email() });

        Assert.Equal(HttpStatusCode.ServiceUnavailable, resp.StatusCode);
        Assert.Equal("application/problem+json", resp.Content.Headers.ContentType?.MediaType);
        Assert.Equal(0L, await factory.CountAsync("SELECT COUNT(*) FROM email_verification_challenges"));
        Assert.Equal(0L, await factory.CountAsync("SELECT COUNT(*) FROM email_outbox"));
    }

    [Fact]
    public async Task ResetPassword_WhenDeliveryDisabled_StaysMapped_BogusTokenReturns400()
    {
        // Like verify-email: an already-issued link must remain consumable without SMTP.
        await using var factory = new CapabilityApiFactory(verification: true);
        var resp = await factory.CreateClient().PostAsJsonAsync("/v1/auth/reset-password", new { token = "bogus-token", password = "a-valid-password-12" });
        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
    }

    [Fact]
    public async Task Resend_WhenDeliveryDisabled_Returns503_AndCreatesNothing()
    {
        await using var factory = new CapabilityApiFactory(verification: true);
        await factory.ResetDatabaseAsync();
        var client = factory.CreateClient();

        var resp = await client.PostAsJsonAsync("/v1/auth/resend-verification", new { email = Email() });

        Assert.Equal(HttpStatusCode.ServiceUnavailable, resp.StatusCode);
        Assert.Equal(0L, await factory.CountAsync("SELECT COUNT(*) FROM email_verification_challenges"));
        Assert.Equal(0L, await factory.CountAsync("SELECT COUNT(*) FROM email_outbox"));
    }

    [Fact]
    public async Task VerifyEmail_RemainsMapped_WhenDeliveryDisabled()
    {
        await using var factory = new CapabilityApiFactory(verification: true);
        var client = factory.CreateClient();

        // Route exists (not 404): a bogus token yields a generic 400, not "not found".
        var resp = await client.PostAsJsonAsync("/v1/auth/verify-email", new { token = "bogus-token", password = "a-valid-password-12" });
        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
    }

    // ---- No verification secrets: auth endpoints not mapped ----

    [Fact]
    public async Task AuthRoutes_NotMapped_WhenVerificationDisabled()
    {
        await using var factory = new CapabilityApiFactory(verification: false);
        var client = factory.CreateClient();

        Assert.Equal(HttpStatusCode.NotFound, (await client.PostAsJsonAsync("/v1/auth/register", new { email = Email() })).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await client.PostAsJsonAsync("/v1/auth/verify-email", new { token = "x", password = "a-valid-password-12" })).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await client.PostAsJsonAsync("/v1/auth/resend-verification", new { email = Email() })).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await client.PostAsJsonAsync("/v1/auth/forgot-password", new { email = Email() })).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await client.PostAsJsonAsync("/v1/auth/reset-password", new { token = "x", password = "a-valid-password-12" })).StatusCode);
        // Health still works.
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/health")).StatusCode);
    }

    // ---- /health stays minimal (no capability leakage) ----

    [Fact]
    public async Task Health_StaysMinimal_NoCapabilityLeakage()
    {
        await using var factory = new CapabilityApiFactory(verification: true);
        var client = factory.CreateClient();

        var json = await client.GetStringAsync("/health");
        using var doc = JsonDocument.Parse(json);
        var names = doc.RootElement.EnumerateObject().Select(p => p.Name).OrderBy(n => n).ToArray();
        Assert.Equal(new[] { "service", "status" }, names); // only service + status; no capabilities block
    }
}
