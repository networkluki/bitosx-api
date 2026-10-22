using BitosX.Application.Mfa;

namespace BitosX.Application.Abstractions.Persistence;

/// <summary>An account's TOTP row: pending until <see cref="ConfirmedAt"/> is set by a first valid code.</summary>
public sealed record TotpEnrollment(Guid AccountId, ProtectedTotpSecret Secret, DateTime CreatedAt, DateTime? ConfirmedAt, long? LastUsedStep)
{
    public bool IsConfirmed => ConfirmedAt is not null;
}

public enum TotpPendingOutcome
{
    Stored,
    AlreadyConfirmed,
}

public enum TotpConfirmOutcome
{
    Confirmed,
    NotPending,
}

/// <summary>
/// Persistence for the second factor: the encrypted TOTP secret, its replay marker, and the
/// account's recovery-code verifiers. Available with the Login capability (it needs only the DB);
/// the crypto that opens the secret is a separate capability.
/// </summary>
public interface ITotpStore
{
    Task<TotpEnrollment?> GetAsync(Guid accountId, CancellationToken cancellationToken = default);

    /// <summary>Stores a new pending secret, replacing a previous pending one. Refuses when TOTP is already confirmed.</summary>
    Task<TotpPendingOutcome> StorePendingAsync(Guid accountId, ProtectedTotpSecret secret, DateTime nowUtc, CancellationToken cancellationToken = default);

    /// <summary>
    /// FOR UPDATE the pending row, mark it confirmed with <paramref name="usedStep"/> as the first used step,
    /// and replace the account's recovery codes with <paramref name="recoveryCodeVerifiers"/> — one transaction.
    /// </summary>
    Task<TotpConfirmOutcome> ConfirmAsync(Guid accountId, long usedStep, IReadOnlyList<byte[]> recoveryCodeVerifiers, DateTime nowUtc, CancellationToken cancellationToken = default);

    /// <summary>
    /// Replay guard: records <paramref name="step"/> as used iff TOTP is confirmed and the step is above the last
    /// used one. Returns false when the step was already used (or is older) — the code must then be rejected.
    /// </summary>
    Task<bool> TryConsumeStepAsync(Guid accountId, long step, CancellationToken cancellationToken = default);

    /// <summary>Marks the recovery code used iff it belongs to the account and is unused (single use, atomic).</summary>
    Task<bool> TryConsumeRecoveryCodeAsync(Guid accountId, byte[] verifier, DateTime nowUtc, CancellationToken cancellationToken = default);

    Task<int> CountUnusedRecoveryCodesAsync(Guid accountId, CancellationToken cancellationToken = default);

    /// <summary>Replaces every recovery code of a confirmed enrollment. Returns false when TOTP is not confirmed.</summary>
    Task<bool> ReplaceRecoveryCodesAsync(Guid accountId, IReadOnlyList<byte[]> recoveryCodeVerifiers, DateTime nowUtc, CancellationToken cancellationToken = default);

    /// <summary>Removes the TOTP row, every recovery code and every open second-step challenge of the account.</summary>
    Task DisableAsync(Guid accountId, CancellationToken cancellationToken = default);
}
