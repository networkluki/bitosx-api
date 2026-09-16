using BitosX.Application.Email;
using MailKit.Net.Smtp;
using MailKit.Security;
using Microsoft.Extensions.Logging;
using MimeKit;

namespace BitosX.Infrastructure.Email;

/// <summary>
/// Sends mail via Gmail SMTP over STARTTLS (smtp.gmail.com:587). TLS certificate
/// validation is left at MailKit's secure default (no bypass callback). SMTP/Gmail
/// errors are isolated: they are logged without credentials/bodies and surfaced as
/// a generic <see cref="EmailSendResult.Failed"/> — never to API clients.
/// </summary>
public sealed class MailKitGmailEmailSender : IEmailSender
{
    // Only STARTTLS submission (587) or implicit TLS (465) are permitted — never plaintext.
    public const SecureSocketOptions SocketOptions = SecureSocketOptions.StartTls;

    private readonly SmtpOptions _smtp;
    private readonly EmailOptions _email;
    private readonly ILogger<MailKitGmailEmailSender> _logger;

    public MailKitGmailEmailSender(SmtpOptions smtp, EmailOptions email, ILogger<MailKitGmailEmailSender> logger)
    {
        if (string.IsNullOrWhiteSpace(smtp.Host)) throw new InvalidOperationException("SMTP host is required.");
        if (smtp.Port is not (587 or 465)) throw new InvalidOperationException("SMTP port must be 587 (STARTTLS) or 465.");
        if (string.IsNullOrWhiteSpace(smtp.Username)) throw new InvalidOperationException("SMTP username is required.");
        if (string.IsNullOrWhiteSpace(smtp.AppPassword)) throw new InvalidOperationException("SMTP app password is required.");
        if (string.IsNullOrWhiteSpace(email.FromAddress)) throw new InvalidOperationException("From address is required.");

        _smtp = smtp;
        _email = email;
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
        try
        {
            using var client = new SmtpClient { Timeout = (int)_smtp.Timeout.TotalMilliseconds };
            await client.ConnectAsync(_smtp.Host, _smtp.Port, SocketOptions, cancellationToken).ConfigureAwait(false);
            await client.AuthenticateAsync(_smtp.Username, _smtp.AppPassword, cancellationToken).ConfigureAwait(false);
            await client.SendAsync(BuildMessage(message), cancellationToken).ConfigureAwait(false);
            await client.DisconnectAsync(quit: true, cancellationToken).ConfigureAwait(false);
            return EmailSendResult.Sent;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Do not surface Gmail/SMTP server text; log a generic failure only.
            _logger.LogWarning("Verification email delivery failed (SMTP send error).");
            return EmailSendResult.Failed;
        }
    }
}
