using BitosX.Application.Abstractions.Persistence;
using Dapper;

namespace BitosX.Infrastructure.Persistence;

/// <summary>
/// Dapper-backed <see cref="IAccountDeletionStore"/> over MariaDB. Locks the account row (no state
/// predicates in the locking read), re-checks that it is still the account the caller verified (verified,
/// enabled, and the exact PHC compared ordinally in C# — never through a column collation), then deletes
/// it. Foreign keys cascade to challenges (and through them outbox rows), sessions (and through them
/// refresh tokens) and vault_blobs, so nothing account-owned survives the commit.
/// </summary>
public sealed class AccountDeletionStore : IAccountDeletionStore
{
    private sealed record AccountLockRow(Guid Id, DateTime? EmailVerifiedAt, string? PasswordHash, DateTime? DisabledAt);

    private readonly BitosxConnectionFactory _connectionFactory;

    public AccountDeletionStore(BitosxConnectionFactory connectionFactory) => _connectionFactory = connectionFactory;

    public async Task<AccountDeleteOutcome> DeleteAccountAsync(
        Guid accountId, string expectedPasswordHash, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(expectedPasswordHash);

        await using var connection = await _connectionFactory.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using var tx = await connection.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);

        var locked = await connection.QuerySingleOrDefaultAsync<AccountLockRow>(new CommandDefinition(
            "SELECT id, email_verified_at, password_hash, disabled_at FROM accounts WHERE id = @accountId FOR UPDATE;",
            new { accountId }, tx, cancellationToken: cancellationToken)).ConfigureAwait(false);

        var deletable = locked is not null
            && locked.EmailVerifiedAt is not null
            && locked.DisabledAt is null
            && string.Equals(locked.PasswordHash, expectedPasswordHash, StringComparison.Ordinal);
        if (!deletable)
        {
            await tx.RollbackAsync(cancellationToken).ConfigureAwait(false);
            return AccountDeleteOutcome.InvalidAccountState;
        }

        var rows = await connection.ExecuteAsync(new CommandDefinition(
            "DELETE FROM accounts WHERE id = @accountId;",
            new { accountId }, tx, cancellationToken: cancellationToken)).ConfigureAwait(false);

        if (rows != 1)
        {
            await tx.RollbackAsync(cancellationToken).ConfigureAwait(false);
            return AccountDeleteOutcome.InvalidAccountState;
        }

        await tx.CommitAsync(cancellationToken).ConfigureAwait(false);
        return AccountDeleteOutcome.Deleted;
    }
}
