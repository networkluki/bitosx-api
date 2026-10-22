namespace BitosX.Application.Verification;

/// <summary>Purpose values stored in <c>email_verification_challenges.purpose</c>. A token is bound to exactly one.</summary>
public static class ChallengePurposes
{
    /// <summary>Activates an unverified account and sets its first password.</summary>
    public const string EmailVerification = "email_verification";

    /// <summary>Replaces the password of a verified account and revokes all of its sessions.</summary>
    public const string PasswordReset = "password_reset";
}

/// <summary>
/// A single-use emailed challenge bound to an account and a purpose.
///
/// The token is NEVER stored in plaintext: only a cryptographic
/// hash (<see cref="TokenHash"/>) is persisted. All timestamps are UTC.
/// </summary>
public sealed record EmailVerificationChallenge
{
    public Guid Id { get; init; }

    public Guid AccountId { get; init; }

    /// <summary>What consuming the token does; see <see cref="ChallengePurposes"/>.</summary>
    public string Purpose { get; init; } = ChallengePurposes.EmailVerification;

    /// <summary>Hash of the token (never the plaintext token).</summary>
    public required byte[] TokenHash { get; init; }

    public DateTime CreatedAt { get; init; }

    public DateTime ExpiresAt { get; init; }

    /// <summary>Set when the challenge is consumed; enforces single use.</summary>
    public DateTime? ConsumedAt { get; init; }

    public int AttemptCount { get; init; }
}
