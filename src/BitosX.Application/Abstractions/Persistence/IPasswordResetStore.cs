using BitosX.Application.Email;
using BitosX.Application.Verification;

namespace BitosX.Application.Abstractions.Persistence;

public enum PasswordResetIssueOutcome
{
    Issued,
    SkippedTooSoon,
    AccountNotEligible,

    /// <summary>The active reset challenge's email is currently leased by a dispatcher (in-flight); not invalidated.</summary>
    SkippedDeliveryInProgress,
}

public enum PasswordResetOutcome
{
    Reset,
    InvalidOrExpired,
}

/// <summary>
/// Persistence for password-reset challenges (purpose <see cref="ChallengePurposes.PasswordReset"/>
/// in the shared challenge table). Same two-phase model as email verification: a non-locking
/// pre-check (<see cref="FindActiveChallengeByVerifierAsync"/>), then Argon2 outside any lock, then
/// an authoritative locked transaction (<see cref="FinalizeResetAsync"/>). Only a verified, enabled
/// account with a password can be reset; an unverified account must finish verification instead.
/// </summary>
public interface IPasswordResetStore
{
    /// <summary>
    /// FOR UPDATE the eligible account, invalidate its active reset challenges (not its verification
    /// challenges), then insert the new challenge + outbox. Enforces the min re-issue interval and never
    /// invalidates a challenge whose email is in flight.
    /// </summary>
    Task<PasswordResetIssueOutcome> IssueChallengeAsync(
        Guid accountId,
        EmailVerificationChallenge newChallenge,
        EmailOutboxMessage newOutbox,
        DateTime nowUtc,
        TimeSpan minReissueInterval,
        CancellationToken cancellationToken = default);

    /// <summary>Non-locking pre-check: an active reset challenge whose account is still eligible.</summary>
    Task<ActiveChallengeView?> FindActiveChallengeByVerifierAsync(
        byte[] verifierHash, DateTime nowUtc, CancellationToken cancellationToken = default);

    /// <summary>
    /// FOR UPDATE the challenge/account, read an authoritative timestamp AFTER the lock, then in one
    /// transaction: replace <c>password_hash</c>, consume the challenge, invalidate the account's other
    /// active reset challenges, and revoke every session and refresh token of the account. Rolls back
    /// to <see cref="PasswordResetOutcome.InvalidOrExpired"/> if expired or if state changed.
    /// </summary>
    Task<PasswordResetOutcome> FinalizeResetAsync(
        byte[] verifierHash, string passwordHashPhc, CancellationToken cancellationToken = default);
}
