namespace BitosX.Application.Verification;

/// <summary>
/// A single-use phone (OTP) verification challenge bound to an account.
///
/// The pending phone number stays HERE until verification succeeds; it must not
/// be written to Account.PhoneE164 before then. The OTP code is NEVER stored in
/// plaintext: only a keyed hash (<see cref="CodeHash"/>) is persisted. The
/// future OTP scheme is HMAC-SHA256 over (AccountId, NormalizedPhoneNumber,
/// Code) with a server-side pepper; the pepper is not stored in the row.
/// All timestamps are UTC.
/// </summary>
public sealed record PhoneVerificationChallenge
{
    public Guid Id { get; init; }

    public Guid AccountId { get; init; }

    /// <summary>The phone being verified; promoted to the account only on success.</summary>
    public required string PendingPhoneE164 { get; init; }

    /// <summary>Keyed hash (HMAC-SHA256) of the OTP code — never the plaintext code.</summary>
    public required byte[] CodeHash { get; init; }

    public DateTime CreatedAt { get; init; }

    /// <summary>Expiry; default policy TTL is 10 minutes.</summary>
    public DateTime ExpiresAt { get; init; }

    public DateTime? ConsumedAt { get; init; }

    public int AttemptCount { get; init; }

    /// <summary>Maximum allowed attempts; default policy is 5.</summary>
    public int MaxAttempts { get; init; }
}
