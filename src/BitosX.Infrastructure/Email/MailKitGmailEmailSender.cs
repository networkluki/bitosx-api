using BitosX.Application.Email;
using MailKit.Security;
using Microsoft.Extensions.Logging;
using MimeKit;

namespace BitosX.Infrastructure.Email;

/// <summary>
/// Sends mail via Gmail SMTP over STARTTLS on port 587. TLS certificate validation is
/// left at MailKit's secure default (no bypass). The ENTIRE attempt (connect + auth +
/// send + disconnect) is bounded by an overall deadline via a linked cancellation
/// token — MailKit's socket Timeout alone does not bound the full sequence. SMTP/Gmail
/// errors are isolated: logged generically (no credentials/bodies) and surfaced as
/// <see cref="EmailSendResult.Failed"/>; never to API clients.
/// </summary>
public sealed class MailKitGmailEmailSender : IEmailSender
{
    // v1 supports only STARTTLS submission on 587. Implicit TLS (465) is intentionally
    // NOT accepted (it would require SslOnConnect + its own tests).
    public const int RequiredPort = 587;
    public const SecureSocketOptions SocketOptions = SecureSocketOptions.StartTls;

    private readonly SmtpOptions _smtp;
    private readonly EmailOptions _email;
    private readonly ISmtpTransportFactory _transportFactory;
    private readonly ILogger<MailKitGmailEmailSender> _logger;

    public MailKitGmailEmailSender(
        SmtpOptions smtp, EmailOptions email, ISmtpTransportFactory transportFactory, ILogger<MailKitGmailEmailSender> logger)
    {
        if (string.IsNullOrWhiteSpace(smtp.Host)) throw new InvalidOperationException("SMTP host is required.");
        if (smtp.Port != RequiredPort) throw new InvalidOperationException($"SMTP port must be {RequiredPort} (STARTTLS).");
        if (string.IsNullOrWhiteSpace(smtp.Username)) throw new InvalidOperationException("SMTP username is required.");
        if (string.IsNullOrWhiteSpace(smtp.AppPassword)) throw new InvalidOperationException("SMTP app password is required.");
        if (string.IsNullOrWhiteSpace(email.FromAddress)) throw new InvalidOperationException("From address is required.");
        if (smtp.AttemptTimeout <= TimeSpan.Zero) throw new InvalidOperationException("SMTP AttemptTimeout must be positive.");

        _smtp = smtp;
        _email = email;
        _transportFactory = transportFactory;
        _logger = logger;
    }

    /// <summary>Builds the MIME message (no network). Exposed for testing.</summary>
    public MimeMessage BuildMessage(EmailMessage message)
    {
        var mime = new MimeMessage();
        mime.From.Add(new MailboxAddress(_email.FromName, _email.FromAddress));
        mime.To.Add(MailboxAddress.Parse(message.ToAddress));
        mime.Subject = message.Subject;
        mime.Body = new BodyBuilder { TextBody = message.TextBody, HtmlBody = message.HtmlBody }.ToMessageBody();
        return mime;
    }

    public async Task<EmailSendResult> SendAsync(EmailMessage message, CancellationToken cancellationToken = default)
    {
        // Overall attempt deadline: bounds the entire connect→auth→send→disconnect sequence.
        using var attemptCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        attemptCts.CancelAfter(_smtp.AttemptTimeout);
        var token = attemptCts.Token;

        try
        {
            await using var transport = _transportFactory.Create();
            transport.Timeout = (int)_smtp.SocketTimeout.TotalMilliseconds;
            await transport.ConnectAsync(_smtp.Host, _smtp.Port, SocketOptions, token).ConfigureAwait(false);
            await transport.AuthenticateAsync(_smtp.Username, _smtp.AppPassword, token).ConfigureAwait(false);
            await transport.SendAsync(BuildMessage(message), token).ConfigureAwait(false);
            await transport.DisconnectAsync(quit: true, token).ConfigureAwait(false);
            return EmailSendResult.Sent;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw; // caller-requested cancellation propagates
        }
        catch (OperationCanceledException)
        {
            _logger.LogWarning("Verification email delivery timed out (attempt deadline exceeded).");
            return EmailSendResult.Failed;
        }
        catch (Exception)
        {
            _logger.LogWarning("Verification email delivery failed (SMTP error).");
            return EmailSendResult.Failed;
        }
    }
}
