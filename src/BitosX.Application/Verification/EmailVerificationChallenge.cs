namespace BitosX.Application.Verification;

/// <summary>
/// A single-use email verification challenge bound to an account.
///
/// The verification token is NEVER stored in plaintext: only a cryptographic
/// hash (<see cref="TokenHash"/>) is persisted. All timestamps are UTC.
/// </summary>
public sealed record EmailVerificationChallenge
{
    public Guid Id { get; init; }

    public Guid AccountId { get; init; }

    /// <summary>Hash of the verification token (never the plaintext token).</summary>
    public required byte[] TokenHash { get; init; }

    public DateTime CreatedAt { get; init; }

    public DateTime ExpiresAt { get; init; }

    /// <summary>Set when the challenge is consumed; enforces single use.</summary>
    public DateTime? ConsumedAt { get; init; }

    public int AttemptCount { get; init; }
}
