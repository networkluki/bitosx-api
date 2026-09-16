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
}
