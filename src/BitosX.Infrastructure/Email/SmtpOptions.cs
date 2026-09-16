namespace BitosX.Infrastructure.Email;

/// <summary>Gmail SMTP settings. The app password is a secret (user-secrets only).</summary>
public sealed class SmtpOptions
{
    public string Host { get; set; } = "smtp.gmail.com";
    public int Port { get; set; } = 587; // STARTTLS submission port
    public string Username { get; set; } = string.Empty;
    public string AppPassword { get; set; } = string.Empty;
}
