using BitosX.Application.Abstractions.Persistence;
using BitosX.Application.Email;
using BitosX.Application.Verification;
using Dapper;

namespace BitosX.Infrastructure.Persistence;

/// <summary>Dapper-backed <see cref="IEmailVerificationStore"/> over MariaDB.</summary>
public sealed class EmailVerificationStore : IEmailVerificationStore
{
    private sealed record FinalizeRow(Guid Id, Guid AccountId);

    private readonly BitosxConnectionFactory _connectionFactory;

    public EmailVerificationStore(BitosxConnectionFactory connectionFactory)
        => _connectionFactory = connectionFactory;

    public async Task<ActiveChallengeView?> FindActiveChallengeByVerifierAsync(
        byte[] verifierHash, DateTime nowUtc, CancellationToken cancellationToken = default)
    {
        await using var connection = await _connectionFactory.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);

        // Non-locking pre-check: active challenge whose account is still unverified.
        const string sql =
            """
            SELECT c.id AS ChallengeId, c.account_id AS AccountId, c.expires_at AS ExpiresAt
            FROM email_verification_challenges c
            JOIN accounts a ON a.id = c.account_id
            WHERE c.token_hash = @verifierHash
              AND c.consumed_at IS NULL
              AND c.invalidated_at IS NULL
              AND c.expires_at > @nowUtc
              AND a.email_verified_at IS NULL
              AND a.password_hash IS NULL;
            """;

        return await connection.QuerySingleOrDefaultAsync<ActiveChallengeView>(
            new CommandDefinition(sql, new { verifierHash, nowUtc }, cancellationToken: cancellationToken)).ConfigureAwait(false);
    }

    public async Task<VerificationOutcome> FinalizeVerificationAsync(
        byte[] verifierHash, string passwordHashPhc, DateTime nowUtc, CancellationToken cancellationToken = default)
    {
        await using var connection = await _connectionFactory.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using var tx = await connection.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);

        // Authoritative re-check under a row lock.
        var row = await connection.QuerySingleOrDefaultAsync<FinalizeRow>(
            new CommandDefinition(
                """
                SELECT c.id AS Id, c.account_id AS AccountId
                FROM email_verification_challenges c
                JOIN accounts a ON a.id = c.account_id
                WHERE c.token_hash = @verifierHash
                  AND c.consumed_at IS NULL
                  AND c.invalidated_at IS NULL
                  AND c.expires_at > @nowUtc
                  AND a.email_verified_at IS NULL
                  AND a.password_hash IS NULL
                FOR UPDATE;
                """, new { verifierHash, nowUtc }, tx, cancellationToken: cancellationToken)).ConfigureAwait(false);

        if (row is null)
        {
            await tx.RollbackAsync(cancellationToken).ConfigureAwait(false);
            return VerificationOutcome.InvalidOrExpired;
        }

        var accountRows = await connection.ExecuteAsync(new CommandDefinition(
            """
            UPDATE accounts
            SET password_hash = @passwordHashPhc, email_verified_at = @nowUtc, updated_at = @nowUtc
            WHERE id = @accountId AND email_verified_at IS NULL AND password_hash IS NULL;
            """,
            new { passwordHashPhc, nowUtc, accountId = row.AccountId }, tx, cancellationToken: cancellationToken)).ConfigureAwait(false);

        var challengeRows = await connection.ExecuteAsync(new CommandDefinition(
            """
            UPDATE email_verification_challenges
            SET consumed_at = @nowUtc
            WHERE id = @challengeId AND consumed_at IS NULL AND invalidated_at IS NULL;
            """,
            new { nowUtc, challengeId = row.Id }, tx, cancellationToken: cancellationToken)).ConfigureAwait(false);

        if (accountRows != 1 || challengeRows != 1)
        {
            await tx.RollbackAsync(cancellationToken).ConfigureAwait(false);
            return VerificationOutcome.InvalidOrExpired;
        }

        await tx.CommitAsync(cancellationToken).ConfigureAwait(false);
        return VerificationOutcome.Verified;
    }

    public async Task<ResendOutcome> ReplaceActiveChallengeAsync(
        Guid accountId, EmailVerificationChallenge newChallenge, EmailOutboxMessage newOutbox,
        DateTime nowUtc, TimeSpan minReissueInterval, CancellationToken cancellationToken = default)
    {
        await using var connection = await _connectionFactory.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using var tx = await connection.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);

        // Lock the account; only unverified accounts are eligible.
        var eligible = await connection.QuerySingleOrDefaultAsync<Guid?>(
            new CommandDefinition(
                "SELECT id FROM accounts WHERE id = @accountId AND email_verified_at IS NULL FOR UPDATE;",
                new { accountId }, tx, cancellationToken: cancellationToken)).ConfigureAwait(false);

        if (eligible is null)
        {
            await tx.RollbackAsync(cancellationToken).ConfigureAwait(false);
            return ResendOutcome.AccountNotEligible;
        }

        // Min re-issue interval: reject if the newest active challenge is too young.
        var newestActiveCreatedAt = await connection.QuerySingleOrDefaultAsync<DateTime?>(
            new CommandDefinition(
                """
                SELECT MAX(created_at) FROM email_verification_challenges
                WHERE account_id = @accountId AND consumed_at IS NULL AND invalidated_at IS NULL AND expires_at > @nowUtc;
                """, new { accountId, nowUtc }, tx, cancellationToken: cancellationToken)).ConfigureAwait(false);

        if (newestActiveCreatedAt is { } created && (nowUtc - created) < minReissueInterval)
        {
            await tx.RollbackAsync(cancellationToken).ConfigureAwait(false);
            return ResendOutcome.SkippedTooSoon;
        }

        await connection.ExecuteAsync(new CommandDefinition(
            """
            UPDATE email_verification_challenges
            SET invalidated_at = @nowUtc
            WHERE account_id = @accountId AND consumed_at IS NULL AND invalidated_at IS NULL;
            """, new { accountId, nowUtc }, tx, cancellationToken: cancellationToken)).ConfigureAwait(false);

        await connection.ExecuteAsync(new CommandDefinition(
            """
            INSERT INTO email_verification_challenges
                (id, account_id, token_hash, created_at, expires_at, consumed_at, invalidated_at, attempt_count)
            VALUES
                (@Id, @AccountId, @TokenHash, @CreatedAt, @ExpiresAt, NULL, NULL, 0);
            """, newChallenge, tx, cancellationToken: cancellationToken)).ConfigureAwait(false);

        await connection.ExecuteAsync(new CommandDefinition(
            OutboxInsert.Sql, OutboxInsert.Params(newOutbox), tx, cancellationToken: cancellationToken)).ConfigureAwait(false);

        await tx.CommitAsync(cancellationToken).ConfigureAwait(false);
        return ResendOutcome.Replaced;
    }
}
