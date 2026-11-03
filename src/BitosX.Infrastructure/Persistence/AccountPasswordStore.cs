using BitosX.Application.Abstractions.Persistence;
using BitosX.Application.Verification;
using Dapper;

namespace BitosX.Infrastructure.Persistence;

/// <summary>
/// Dapper-backed <see cref="IAccountPasswordStore"/> over MariaDB. One transaction in the canonical lock order
/// accounts → email_verification_challenges → sessions → refresh_tokens (the same order as password reset and
/// logout-all): lock the account, re-check its state and the exact PHC the caller verified (ordinal, in C#,
/// never through the column collation), replace the hash, invalidate open reset links, and revoke every session
/// except the caller's together with their refresh tokens.
/// </summary>
public sealed class AccountPasswordStore : IAccountPasswordStore
{
    private sealed record AccountLockRow(Guid Id, DateTime? EmailVerifiedAt, string? PasswordHash, DateTime? DisabledAt);

    private readonly BitosxConnectionFactory _connectionFactory;
    private readonly TimeProvider _clock;

    public AccountPasswordStore(BitosxConnectionFactory connectionFactory, TimeProvider clock)
    {
        _connectionFactory = connectionFactory ?? throw new ArgumentNullException(nameof(connectionFactory));
        _clock = clock ?? throw new ArgumentNullException(nameof(clock));
    }

    public async Task<PasswordChangeOutcome> ChangePasswordAsync(
        Guid accountId, Guid keepSessionId, string expectedPasswordHash, string newPasswordHash, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(expectedPasswordHash);
        ArgumentException.ThrowIfNullOrEmpty(newPasswordHash);
        if (accountId == Guid.Empty) throw new ArgumentException("An account id is required.", nameof(accountId));

        await using var connection = await _connectionFactory.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using var tx = await connection.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);

        // Lock first, evaluate state after (no state predicates in the locking read).
        var account = await connection.QuerySingleOrDefaultAsync<AccountLockRow>(new CommandDefinition(
            "SELECT id, email_verified_at, password_hash, disabled_at FROM accounts WHERE id = @accountId FOR UPDATE;",
            new { accountId }, tx, cancellationToken: cancellationToken)).ConfigureAwait(false);

        var capable = account is not null
            && account.EmailVerifiedAt is not null
            && account.DisabledAt is null
            && string.Equals(account.PasswordHash, expectedPasswordHash, StringComparison.Ordinal);
        if (!capable)
        {
            await tx.RollbackAsync(cancellationToken).ConfigureAwait(false);
            return PasswordChangeOutcome.InvalidAccountState;
        }

        var now = _clock.GetUtcNow().UtcDateTime;
        var rows = await connection.ExecuteAsync(new CommandDefinition(
            "UPDATE accounts SET password_hash = @newPasswordHash, updated_at = @now WHERE id = @accountId;",
            new { newPasswordHash, now, accountId }, tx, cancellationToken: cancellationToken)).ConfigureAwait(false);
        if (rows != 1)
        {
            await tx.RollbackAsync(cancellationToken).ConfigureAwait(false);
            return PasswordChangeOutcome.InvalidAccountState;
        }

        // An open reset link would let whoever holds the mailbox undo the change: invalidate them all.
        await connection.ExecuteAsync(new CommandDefinition(
            """
            UPDATE email_verification_challenges
            SET invalidated_at = @now
            WHERE account_id = @accountId AND purpose = @purpose AND consumed_at IS NULL AND invalidated_at IS NULL;
            """,
            new { now, accountId, purpose = ChallengePurposes.PasswordReset }, tx, cancellationToken: cancellationToken)).ConfigureAwait(false);

        // Every other session (and its refresh tokens) is signed out; the caller's session stays valid.
        var sessionIds = (await connection.QueryAsync<Guid>(new CommandDefinition(
            "SELECT id FROM sessions WHERE account_id = @accountId AND revoked_at IS NULL AND id <> @keepSessionId ORDER BY id FOR UPDATE;",
            new { accountId, keepSessionId }, tx, cancellationToken: cancellationToken)).ConfigureAwait(false)).ToList();

        if (sessionIds.Count > 0)
        {
            _ = await connection.QueryAsync<Guid>(new CommandDefinition(
                "SELECT id FROM refresh_tokens WHERE session_id IN @sessionIds ORDER BY id FOR UPDATE;",
                new { sessionIds }, tx, cancellationToken: cancellationToken)).ConfigureAwait(false);

            await connection.ExecuteAsync(new CommandDefinition(
                "UPDATE sessions SET revoked_at = @now WHERE id IN @sessionIds AND revoked_at IS NULL;",
                new { now, sessionIds }, tx, cancellationToken: cancellationToken)).ConfigureAwait(false);
            await connection.ExecuteAsync(new CommandDefinition(
                "UPDATE refresh_tokens SET revoked_at = @now WHERE session_id IN @sessionIds AND revoked_at IS NULL;",
                new { now, sessionIds }, tx, cancellationToken: cancellationToken)).ConfigureAwait(false);
        }

        await tx.CommitAsync(cancellationToken).ConfigureAwait(false);
        return PasswordChangeOutcome.Changed;
    }
}
