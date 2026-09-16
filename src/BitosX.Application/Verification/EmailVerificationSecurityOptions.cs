namespace BitosX.Application.Verification;

/// <summary>
/// Server-side secret for email-verification token verifiers. The pepper is a
/// high-entropy random string held only in the secret store (user-secrets /
/// production injection) — never in MariaDB, Git, or appsettings.
/// </summary>
public sealed class EmailVerificationSecurityOptions
{
    /// <summary>HMAC pepper (a long random string). Required at runtime.</summary>
    public string Pepper { get; set; } = string.Empty;

    /// <summary>Token time-to-live; policy default is 30 minutes.</summary>
    public TimeSpan TokenLifetime { get; set; } = TimeSpan.FromMinutes(30);

    /// <summary>Minimum interval between resend re-issues for one account (anti-mail-bomb stopgap).</summary>
    public TimeSpan MinResendInterval { get; set; } = TimeSpan.FromSeconds(60);
}
