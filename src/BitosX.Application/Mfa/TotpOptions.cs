namespace BitosX.Application.Mfa;

/// <summary>
/// Non-secret TOTP (RFC 6238) and second-step policy. The secret that protects stored TOTP secrets
/// (<c>Security:TotpKey</c>) lives in the secret store and gates the Totp capability; nothing here is secret.
/// </summary>
public sealed class TotpOptions
{
    public const string SectionName = "Security:Totp";

    /// <summary>Issuer shown in authenticator apps and embedded in the otpauth URI.</summary>
    public string Issuer { get; set; } = "BitosX";

    /// <summary>RFC 6238 parameters: HMAC-SHA1, 6 digits, 30-second steps (what every authenticator app defaults to).</summary>
    public int Digits { get; set; } = 6;

    public int PeriodSeconds { get; set; } = 30;

    /// <summary>Steps accepted on each side of the current one (1 → a 90-second window) to absorb clock drift.</summary>
    public int WindowSteps { get; set; } = 1;

    /// <summary>Random secret length in bytes (160 bits, the RFC 4226 recommendation).</summary>
    public int SecretBytes { get; set; } = 20;

    /// <summary>How long the second sign-in step may take after the password was accepted.</summary>
    public TimeSpan MfaChallengeLifetime { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>Wrong codes tolerated per challenge before it is invalidated and the password must be entered again.</summary>
    public int MaxMfaAttempts { get; set; } = 5;

    /// <summary>Recovery codes issued when TOTP is confirmed or the codes are regenerated.</summary>
    public int RecoveryCodeCount { get; set; } = 10;

    public void Validate()
    {
        if (string.IsNullOrWhiteSpace(Issuer) || Issuer.Length > 64 || Issuer.Contains(':')) throw new InvalidOperationException($"{SectionName}:Issuer must be 1-64 characters without ':'.");
        if (Digits is < 6 or > 8) throw new InvalidOperationException($"{SectionName}:Digits must be 6, 7 or 8.");
        if (PeriodSeconds is < 15 or > 120) throw new InvalidOperationException($"{SectionName}:PeriodSeconds must be between 15 and 120.");
        if (WindowSteps is < 0 or > 2) throw new InvalidOperationException($"{SectionName}:WindowSteps must be between 0 and 2.");
        if (SecretBytes is < 16 or > 64) throw new InvalidOperationException($"{SectionName}:SecretBytes must be between 16 and 64.");
        if (MfaChallengeLifetime < TimeSpan.FromMinutes(1) || MfaChallengeLifetime > TimeSpan.FromMinutes(30)) throw new InvalidOperationException($"{SectionName}:MfaChallengeLifetimeSeconds must be between 60 and 1800.");
        if (MaxMfaAttempts is < 3 or > 10) throw new InvalidOperationException($"{SectionName}:MaxMfaAttempts must be between 3 and 10.");
        if (RecoveryCodeCount is < 5 or > 20) throw new InvalidOperationException($"{SectionName}:RecoveryCodeCount must be between 5 and 20.");
    }
}
