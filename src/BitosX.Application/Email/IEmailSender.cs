namespace BitosX.Application.Email;

/// <summary>A composed email message (no MailKit types leak into Application).</summary>
public sealed record EmailMessage(string ToAddress, string Subject, string TextBody, string HtmlBody);

/// <summary>Outcome of a delivery attempt (no provider/SMTP detail is surfaced).</summary>
public enum EmailSendResult
{
    Sent,
    Failed,
}

/// <summary>Sends a composed email. Infrastructure implements Gmail SMTP delivery.</summary>
public interface IEmailSender
{
    Task<EmailSendResult> SendAsync(EmailMessage message, CancellationToken cancellationToken = default);
}
