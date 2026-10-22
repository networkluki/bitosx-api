namespace BitosX.Application.Abstractions.Persistence;

/// <summary>
/// Coarse by design: <see cref="InvalidAccountState"/> covers a missing/disabled/unverified account
/// and a password hash that changed since the caller verified it. The caller maps it to one generic
/// failure.
/// </summary>
public enum AccountDeleteOutcome
{
    Deleted,
    InvalidAccountState,
}

/// <summary>
/// Permanent account deletion. The caller has ALREADY verified the account password (Argon2) outside
/// any lock; the store re-checks the exact PHC under the account row lock and deletes the row, which
/// cascades to every account-owned row (challenges, outbox rows, sessions, refresh tokens, vault
/// envelope). No plaintext password ever reaches the store.
/// </summary>
public interface IAccountDeletionStore
{
    Task<AccountDeleteOutcome> DeleteAccountAsync(
        Guid accountId, string expectedPasswordHash, CancellationToken cancellationToken = default);
}
