using BitosX.Application.Email;
using BitosX.Application.Verification;

namespace BitosX.Application.Abstractions.Persistence;

/// <summary>Non-locking snapshot of an active challenge (Phase A pre-check).</summary>
public sealed record ActiveChallengeView(Guid ChallengeId, Guid AccountId, DateTime ExpiresAt);

public enum VerificationOutcome
{
    Verified,
    InvalidOrExpired,
}

public enum ResendOutcome
{
    Replaced,
    SkippedTooSoon,
    AccountNotEligible,

    /// <summary>The active challenge's email is currently leased by a dispatcher (in-flight); not invalidated.</summary>
    SkippedDeliveryInProgress,
}

/// <summary>
/// Persistence for email verification challenges. Verification uses a two-phase
/// model: a non-locking pre-check (<see cref="FindActiveChallengeByVerifierAsync"/>)
/// then, after the caller hashes the password, an authoritative locked
/// transaction (<see cref="FinalizeVerificationAsync"/>). No Argon2/network I/O
/// runs inside the finalize transaction.
/// </summary>
public interface IEmailVerificationStore
{
    Task<ActiveChallengeView?> FindActiveChallengeByVerifierAsync(
        byte[] verifierHash, DateTime nowUtc, CancellationToken cancellationToken = default);

    /// <summary>
    /// Phase C: FOR UPDATE the challenge/account, then read an authoritative timestamp
    /// AFTER the lock is held and evaluate expiry against it (never a caller-supplied
    /// time — the lock may have been waited on). Sets account.password_hash +
    /// email_verified_at and challenge.consumed_at via conditional (affected=1) updates,
    /// all stamped with that same authoritative time. Rolls back to InvalidOrExpired if
    /// expired or if state changed — no partial activation. The store owns the clock.
    /// </summary>
    Task<VerificationOutcome> FinalizeVerificationAsync(
        byte[] verifierHash, string passwordHashPhc, CancellationToken cancellationToken = default);

    /// <summary>
    /// Resend: FOR UPDATE the unverified account, invalidate all active
    /// challenges (invalidated_at, not consumed_at), then insert the new
    /// challenge + outbox. Enforces the min re-issue interval.
    /// </summary>
    Task<ResendOutcome> ReplaceActiveChallengeAsync(
        Guid accountId,
        EmailVerificationChallenge newChallenge,
        EmailOutboxMessage newOutbox,
        DateTime nowUtc,
        TimeSpan minReissueInterval,
        CancellationToken cancellationToken = default);
}
