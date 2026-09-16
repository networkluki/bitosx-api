using BitosX.Application.Email;
using BitosX.Infrastructure.Email;
using MailKit.Security;
using Microsoft.Extensions.Logging.Abstractions;
using MimeKit;

namespace BitosX.Infrastructure.Tests.Email;

/// <summary>Fake transport that can stall a chosen operation until the attempt deadline cancels it.</summary>
public sealed class FakeSmtpTransport : ISmtpTransport
{
    public enum Step { None, Connect, Authenticate, Send }
    private readonly Step _stallOn;
    public FakeSmtpTransport(Step stallOn) => _stallOn = stallOn;

    public int Timeout { get; set; }

    private static Task StallOrComplete(Step current, Step stall, CancellationToken ct)
        => current == stall ? Task.Delay(System.Threading.Timeout.Infinite, ct) : Task.CompletedTask;

    public Task ConnectAsync(string host, int port, SecureSocketOptions options, CancellationToken ct) => StallOrComplete(Step.Connect, _stallOn, ct);
    public Task AuthenticateAsync(string username, string password, CancellationToken ct) => StallOrComplete(Step.Authenticate, _stallOn, ct);
    public Task SendAsync(MimeMessage message, CancellationToken ct) => StallOrComplete(Step.Send, _stallOn, ct);
    public Task DisconnectAsync(bool quit, CancellationToken ct) => Task.CompletedTask;
    public ValueTask DisposeAsync() => ValueTask.CompletedTask;
}

internal sealed class FakeSmtpTransportFactory(FakeSmtpTransport.Step stallOn) : ISmtpTransportFactory
{
    public ISmtpTransport Create() => new FakeSmtpTransport(stallOn);
}

public sealed class MailKitGmailEmailSenderTests
{
    private static SmtpOptions ValidSmtp() => new()
    {
        Host = "smtp.gmail.com", Port = 587, Username = "bitosx@example.com", AppPassword = "app-password-value",
        AttemptTimeout = TimeSpan.FromMilliseconds(100), SocketTimeout = TimeSpan.FromMilliseconds(100),
    };

    private static EmailOptions ValidEmail() => new() { FromAddress = "bitosx@example.com", FromName = "BitosX", PublicBaseUrl = "https://vault.bitosx.se" };

    private static MailKitGmailEmailSender Sender(FakeSmtpTransport.Step stallOn = FakeSmtpTransport.Step.None, SmtpOptions? smtp = null)
        => new(smtp ?? ValidSmtp(), ValidEmail(), new FakeSmtpTransportFactory(stallOn), NullLogger<MailKitGmailEmailSender>.Instance);

    private static readonly EmailMessage Msg = new("to@example.com", "Subj", "text", "<p>html</p>");

    [Fact]
    public void UsesStartTls() => Assert.Equal(SecureSocketOptions.StartTls, MailKitGmailEmailSender.SocketOptions);

    [Theory]
    [InlineData(25)]
    [InlineData(465)]   // implicit TLS not supported in v1
    [InlineData(2525)]
    public void Constructor_RejectsNon587Port(int port)
    {
        var smtp = ValidSmtp(); smtp.Port = port;
        Assert.Throws<InvalidOperationException>(() => Sender(smtp: smtp));
    }

    [Fact]
    public void Constructor_Accepts587() => _ = Sender(); // no throw

    [Fact]
    public void Constructor_RequiresCredentials()
    {
        var smtp = ValidSmtp(); smtp.AppPassword = "";
        Assert.Throws<InvalidOperationException>(() => Sender(smtp: smtp));
    }

    [Fact]
    public void BuildMessage_MapsHeadersAndBodies()
    {
        var mime = Sender().BuildMessage(Msg);
        Assert.Equal("Subj", mime.Subject);
        Assert.Equal("to@example.com", mime.To.ToString());
        Assert.Contains("bitosx@example.com", mime.From.ToString());
        Assert.Equal("text", mime.TextBody);
    }

    [Fact]
    public async Task NoStall_Sends() => Assert.Equal(EmailSendResult.Sent, await Sender().SendAsync(Msg));

    [Theory]
    [InlineData(FakeSmtpTransport.Step.Connect)]
    [InlineData(FakeSmtpTransport.Step.Authenticate)]
    [InlineData(FakeSmtpTransport.Step.Send)]
    public async Task OperationStall_HitsAttemptDeadline_ReturnsFailed(FakeSmtpTransport.Step step)
    {
        // AttemptTimeout is 100ms; the stalled op is cancelled by the overall deadline.
        var result = await Sender(step).SendAsync(Msg);
        Assert.Equal(EmailSendResult.Failed, result); // did NOT wait for any lease duration
    }

    [Fact]
    public async Task CallerCancellation_Propagates()
    {
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => Sender(FakeSmtpTransport.Step.Connect).SendAsync(Msg, cts.Token));
    }
}
