using BitosX.Application.Abstractions.Persistence;
using Dapper;

namespace BitosX.Infrastructure.Persistence;

/// <summary>
/// Dapper-backed <see cref="IAccountDeletionStore"/> over MariaDB. Locks the account row, re-checks
/// that it is still the account the caller verified (same exact PHC, verified, enabled), then deletes
/// it. Foreign keys cascade to challenges (and through them outbox rows), sessions (and through them
/// refresh tokens) and vault_blobs, so nothing account-owned survives the commit.
/// </summary>
public sealed class AccountDeletionStore : IAccountDeletionStore
{
    private readonly BitosxConnectionFactory _connectionFactory;

    public AccountDeletionStore(BitosxConnectionFactory connectionFactory) => _connectionFactory = connectionFactory;

    public async Task<AccountDeleteOutcome> DeleteAccountAsync(
        Guid accountId, string expectedPasswordHash, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(expectedPasswordHash);

        await using var connection = await _connectionFactory.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using var tx = await connection.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);

        var locked = await connection.QuerySingleOrDefaultAsync<Guid?>(new CommandDefinition(
            """
            SELECT id FROM accounts
            WHERE id = @accountId AND password_hash = @expectedPasswordHash
              AND email_verified_at IS NOT NULL AND disabled_at IS NULL
            FOR UPDATE;
            """, new { accountId, expectedPasswordHash }, tx, cancellationToken: cancellationToken)).ConfigureAwait(false);

        if (locked is null)
        {
            await tx.RollbackAsync(cancellationToken).ConfigureAwait(false);
            return AccountDeleteOutcome.InvalidAccountState;
        }

        var rows = await connection.ExecuteAsync(new CommandDefinition(
            "DELETE FROM accounts WHERE id = @accountId AND password_hash = @expectedPasswordHash;",
            new { accountId, expectedPasswordHash }, tx, cancellationToken: cancellationToken)).ConfigureAwait(false);

        if (rows != 1)
        {
            await tx.RollbackAsync(cancellationToken).ConfigureAwait(false);
            return AccountDeleteOutcome.InvalidAccountState;
        }

        await tx.CommitAsync(cancellationToken).ConfigureAwait(false);
        return AccountDeleteOutcome.Deleted;
    }
}
