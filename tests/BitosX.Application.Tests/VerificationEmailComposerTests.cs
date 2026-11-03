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

public sealed class EmailPublicBaseUrlValidationTests
{
    private static void Valid(string url, bool loopbackHttp = false) => new EmailOptions { PublicBaseUrl = url }.ValidatePublicBaseUrl(loopbackHttp);

    private static void Invalid(string? url, bool loopbackHttp = false)
        => Assert.Throws<InvalidOperationException>(() => new EmailOptions { PublicBaseUrl = url! }.ValidatePublicBaseUrl(loopbackHttp));

    [Theory]
    [InlineData("https://vault.bitosx.se")]
    [InlineData("https://vault.bitosx.se/")]
    [InlineData("https://vault.bitosx.se:8443")]
    public void HttpsOrigins_AreAccepted(string url) => Valid(url);

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(null)]
    [InlineData("/verify")]
    [InlineData("vault.bitosx.se")]
    [InlineData("http://vault.bitosx.se")]
    [InlineData("http://localhost:5173")]           // loopback http only when explicitly allowed
    [InlineData("ftp://vault.bitosx.se")]
    [InlineData("https://vault.bitosx.se/app")]
    [InlineData("https://vault.bitosx.se?x=1")]
    [InlineData("https://vault.bitosx.se#x")]
    [InlineData("https://user@vault.bitosx.se")]
    public void EverythingElse_FailsClosed(string? url) => Invalid(url);

    [Theory]
    [InlineData("http://localhost:5173")]
    [InlineData("http://127.0.0.1:8080")]
    [InlineData("http://[::1]:8080")]
    public void LoopbackHttp_IsAccepted_OnlyWhenAllowed(string url)
    {
        Valid(url, loopbackHttp: true);
        Invalid(url, loopbackHttp: false);
    }

    [Fact]
    public void NonLoopbackHttp_IsRejected_EvenWhenLoopbackIsAllowed() => Invalid("http://vault.bitosx.se", loopbackHttp: true);
}
