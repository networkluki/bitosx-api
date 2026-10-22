using System.Net;
using System.Net.Http.Json;
using System.Text.Json;

namespace BitosX.Api.Tests;

/// <summary>Phase 1: capability-gated endpoint behavior (SMTP delivery disabled).</summary>
public sealed class CapabilityEndpointTests
{
    private static string Email() => $"user-{Guid.NewGuid():N}@example.com";

    // ---- EmailVerification enabled, EmailDelivery disabled ----

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
