using BitosX.Application.Email;
using BitosX.Infrastructure.Email;
using MailKit.Security;
using Microsoft.Extensions.Logging.Abstractions;

namespace BitosX.Infrastructure.Tests.Email;

public sealed class MailKitGmailEmailSenderTests
{
    private static SmtpOptions ValidSmtp() => new()
    {
        Host = "smtp.gmail.com", Port = 587, Username = "bitosx@example.com", AppPassword = "app-password-value",
    };

    private static EmailOptions ValidEmail() => new()
    {
        FromAddress = "bitosx@example.com", FromName = "BitosX", PublicBaseUrl = "https://vault.bitosx.se",
    };

    private static MailKitGmailEmailSender Sender()
        => new(ValidSmtp(), ValidEmail(), NullLogger<MailKitGmailEmailSender>.Instance);

    [Fact]
    public void UsesStartTls_NotPlaintext()
        => Assert.Equal(SecureSocketOptions.StartTls, MailKitGmailEmailSender.SocketOptions);

    [Theory]
    [InlineData(25)]   // plaintext SMTP
    [InlineData(2525)]
    [InlineData(80)]
    public void Constructor_RejectsInsecurePort(int port)
    {
        var smtp = ValidSmtp();
        smtp.Port = port;
        Assert.Throws<InvalidOperationException>(() => new MailKitGmailEmailSender(smtp, ValidEmail(), NullLogger<MailKitGmailEmailSender>.Instance));
    }

    [Fact]
    public void Constructor_RequiresCredentials()
    {
        var smtp = ValidSmtp(); smtp.AppPassword = "";
        Assert.Throws<InvalidOperationException>(() => new MailKitGmailEmailSender(smtp, ValidEmail(), NullLogger<MailKitGmailEmailSender>.Instance));
    }

    [Fact]
    public void BuildMessage_MapsHeadersAndBodies()
    {
        var mime = Sender().BuildMessage(new EmailMessage("to@example.com", "Subject X", "text body", "<p>html body</p>"));
        Assert.Equal("Subject X", mime.Subject);
        Assert.Equal("to@example.com", mime.To.ToString());
        Assert.Contains("bitosx@example.com", mime.From.ToString());
        Assert.Equal("text body", mime.TextBody);
        Assert.Equal("<p>html body</p>", mime.HtmlBody);
    }
}
