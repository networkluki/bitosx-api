namespace BitosX.Infrastructure.Email;

/// <summary>Gmail SMTP settings. The app password is a secret (user-secrets only).</summary>
public sealed class SmtpOptions
{
    public string Host { get; set; } = "smtp.gmail.com";
    public int Port { get; set; } = 587; // STARTTLS submission port (only 587 supported in v1)
    public string Username { get; set; } = string.Empty;
    public string AppPassword { get; set; } = string.Empty;

    /// <summary>
    /// Overall deadline for the ENTIRE send attempt (connect + auth + send + disconnect),
    /// enforced via a linked cancellation token. This is the value the outbox lease
    /// invariant is validated against. Must be strictly less than the lease.
    /// </summary>
    public TimeSpan AttemptTimeout { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>Low-level MailKit socket read/write timeout (defense in depth; not the overall deadline).</summary>
    public TimeSpan SocketTimeout { get; set; } = TimeSpan.FromSeconds(30);
}
