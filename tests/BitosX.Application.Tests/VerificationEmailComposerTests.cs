using BitosX.Application.Email;
using BitosX.Application.Verification;

namespace BitosX.Application.Tests;

public sealed class VerificationEmailComposerTests
{
    private static VerificationEmailComposer Composer() => new(new EmailOptions
    {
        FromAddress = "bitosx@example.com",
        FromName = "BitosX",
        PublicBaseUrl = "https://vault.bitosx.se",
        VerificationPath = "/verify-email",
        PasswordResetPath = "/reset-password",
    });

    [Fact]
    public void Compose_ContainsIdentityExpiryFragmentLinkAndIgnoreNotice()
    {
        var msg = Composer().Compose("user@example.com", "TOKEN123", DateTime.UtcNow.AddMinutes(30), 30);

        foreach (var body in new[] { msg.TextBody, msg.HtmlBody })
        {
            Assert.Contains("BitosX", body);
            Assert.Contains("30 minutes", body);
            Assert.Contains("https://vault.bitosx.se/verify-email#token=TOKEN123", body); // fragment, not query
            Assert.DoesNotContain("/verify-email?token=", body);
            Assert.Contains("ignore", body, StringComparison.OrdinalIgnoreCase);
        }

        Assert.Equal("user@example.com", msg.ToAddress);
    }

    [Fact]
    public void Compose_LeaksNoSensitiveData()
    {
        var msg = Composer().Compose("user@example.com", "TOKEN123", DateTime.UtcNow.AddMinutes(30), 30);
        var all = msg.TextBody + msg.HtmlBody + msg.Subject;
        foreach (var forbidden in new[] { "password_hash", "token_hash", "argon2", "127.0.0.1", "Server=", "Pepper" })
        {
            Assert.DoesNotContain(forbidden, all, StringComparison.OrdinalIgnoreCase);
        }
    }

    [Fact]
    public void ComposePasswordReset_UsesResetPage_FragmentLink_AndExplainsScope()
    {
        var msg = Composer().ComposePasswordReset("user@example.com", "TOKEN123", DateTime.UtcNow.AddMinutes(30), 30);

        foreach (var body in new[] { msg.TextBody, msg.HtmlBody })
        {
            Assert.Contains("https://vault.bitosx.se/reset-password#token=TOKEN123", body); // fragment, not query
            Assert.DoesNotContain("/reset-password?token=", body);
            Assert.DoesNotContain("/verify-email", body);
            Assert.Contains("30 minutes", body);
            Assert.Contains("master password", body); // the vault is out of scope for a reset
            Assert.Contains("ignore", body, StringComparison.OrdinalIgnoreCase);
        }

        Assert.Equal("user@example.com", msg.ToAddress);
        Assert.DoesNotContain("TOKEN123", msg.Subject);
    }

    [Fact]
    public void ComposePasswordReset_LeaksNoSensitiveData()
    {
        var msg = Composer().ComposePasswordReset("user@example.com", "TOKEN123", DateTime.UtcNow.AddMinutes(30), 30);
        var all = msg.TextBody + msg.HtmlBody + msg.Subject;
        foreach (var forbidden in new[] { "password_hash", "token_hash", "argon2", "127.0.0.1", "Server=", "Pepper" })
        {
            Assert.DoesNotContain(forbidden, all, StringComparison.OrdinalIgnoreCase);
        }
    }
}
