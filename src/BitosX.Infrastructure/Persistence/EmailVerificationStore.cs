using BitosX.Application.Abstractions.Persistence;
using BitosX.Application.Email;
using BitosX.Application.Verification;
using Dapper;

namespace BitosX.Infrastructure.Persistence;

/// <summary>
/// Dapper-backed <see cref="IEmailVerificationStore"/> over MariaDB. Every query is bound to
/// <c>purpose = 'email_verification'</c>, so a password-reset token can never activate an account.
/// </summary>
public sealed class EmailVerificationStore : IEmailVerificationStore
{
    private sealed record FinalizeRow(Guid Id, Guid AccountId, DateTime ExpiresAt);
    private sealed record ActiveOutboxRow(DateTime ChallengeCreatedAt, DateTime? SentAt, DateTime? FailedAt, DateTime? LockedUntil);

    private readonly BitosxConnectionFactory _connectionFactory;
    private readonly TimeProvider _clock;

    public EmailVerificationStore(BitosxConnectionFactory connectionFactory, TimeProvider clock)
    {
        _connectionFactory = connectionFactory;
        _clock = clock;
    }

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
              AND c.purpose = @purpose
              AND c.consumed_at IS NULL
              AND c.invalidated_at IS NULL
              AND c.expires_at > @nowUtc
              AND a.email_verified_at IS NULL
              AND a.password_hash IS NULL
              AND a.disabled_at IS NULL;
            """;

        return await connection.QuerySingleOrDefaultAsync<ActiveChallengeView>(
            new CommandDefinition(sql, new { verifierHash, purpose = ChallengePurposes.EmailVerification, nowUtc }, cancellationToken: cancellationToken)).ConfigureAwait(false);
    }

    public async Task<VerificationOutcome> FinalizeVerificationAsync(
        byte[] verifierHash, string passwordHashPhc, CancellationToken cancellationToken = default)
    {
        await using var connection = await _connectionFactory.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using var tx = await connection.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);

        // Lock the challenge/account WITHOUT an expiry predicate (a caller time could be
        // stale after a lock wait). Expiry is decided against an authoritative timestamp
        // read only AFTER the lock is held (below).
        var row = await connection.QuerySingleOrDefaultAsync<FinalizeRow>(
            new CommandDefinition(
                """
                SELECT c.id AS Id, c.account_id AS AccountId, c.expires_at AS ExpiresAt
                FROM email_verification_challenges c
                JOIN accounts a ON a.id = c.account_id
                WHERE c.token_hash = @verifierHash
                  AND c.purpose = @purpose
                  AND c.consumed_at IS NULL
                  AND c.invalidated_at IS NULL
                  AND a.email_verified_at IS NULL
                  AND a.password_hash IS NULL
                  AND a.disabled_at IS NULL
                FOR UPDATE;
                """, new { verifierHash, purpose = ChallengePurposes.EmailVerification }, tx, cancellationToken: cancellationToken)).ConfigureAwait(false);

        if (row is null)
        {
            await tx.RollbackAsync(cancellationToken).ConfigureAwait(false);
            return VerificationOutcome.InvalidOrExpired;
        }

        // Authoritative time acquired only now that the lock is actually held.
        var nowUtc = _clock.GetUtcNow().UtcDateTime;
        if (row.ExpiresAt <= nowUtc)
        {
            await tx.RollbackAsync(cancellationToken).ConfigureAwait(false);
            return VerificationOutcome.InvalidOrExpired;
        }

        var accountRows = await connection.ExecuteAsync(new CommandDefinition(
            """
            UPDATE accounts
            SET password_hash = @passwordHashPhc, email_verified_at = @nowUtc, updated_at = @nowUtc
            WHERE id = @accountId AND email_verified_at IS NULL AND password_hash IS NULL AND disabled_at IS NULL;
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
        // READ COMMITTED for the same reason as password-reset issuing: record locks only, no gap locks on the
        // challenge range, so adjacent accounts cannot deadlock on each other's challenge insert.
        await using var tx = await connection.BeginTransactionAsync(System.Data.IsolationLevel.ReadCommitted, cancellationToken).ConfigureAwait(false);

        // Lock the account; only unverified accounts are eligible.
        var eligible = await connection.QuerySingleOrDefaultAsync<Guid?>(
            new CommandDefinition(
                "SELECT id FROM accounts WHERE id = @accountId AND email_verified_at IS NULL AND password_hash IS NULL AND disabled_at IS NULL FOR UPDATE;",
                new { accountId }, tx, cancellationToken: cancellationToken)).ConfigureAwait(false);

        if (eligible is null)
        {
            await tx.RollbackAsync(cancellationToken).ConfigureAwait(false);
            return ResendOutcome.AccountNotEligible;
        }

        // Locate + lock the current active challenge and its pending outbox row. The
        // FOR UPDATE on email_outbox coordinates with the dispatcher's ClaimDueAsync
        // (which uses FOR UPDATE SKIP LOCKED): if a delivery is in flight we see its
        // lease; if we lock first the dispatcher skips the row.
        var active = await connection.QuerySingleOrDefaultAsync<ActiveOutboxRow>(
            new CommandDefinition(
                """
                SELECT c.created_at AS ChallengeCreatedAt, o.sent_at AS SentAt,
                       o.failed_at AS FailedAt, o.locked_until AS LockedUntil
                FROM email_verification_challenges c
                JOIN email_outbox o ON o.challenge_id = c.id
                WHERE c.account_id = @accountId AND c.purpose = @purpose
                  AND c.consumed_at IS NULL AND c.invalidated_at IS NULL AND c.expires_at > @nowUtc
                ORDER BY c.created_at DESC
                LIMIT 1
                FOR UPDATE;
                """, new { accountId, purpose = ChallengePurposes.EmailVerification, nowUtc }, tx, cancellationToken: cancellationToken)).ConfigureAwait(false);

        if (active is not null)
        {
            // Delivery currently in progress (leased, not yet terminal): do not invalidate.
            if (active.SentAt is null && active.FailedAt is null && active.LockedUntil is { } lease && lease > nowUtc)
            {
                await tx.RollbackAsync(cancellationToken).ConfigureAwait(false);
                return ResendOutcome.SkippedDeliveryInProgress;
            }

            // Min re-issue interval: reject if the newest active challenge is too young.
            if ((nowUtc - active.ChallengeCreatedAt) < minReissueInterval)
            {
                await tx.RollbackAsync(cancellationToken).ConfigureAwait(false);
                return ResendOutcome.SkippedTooSoon;
            }
        }

        await connection.ExecuteAsync(new CommandDefinition(
            """
            UPDATE email_verification_challenges
            SET invalidated_at = @nowUtc
            WHERE account_id = @accountId AND purpose = @purpose AND consumed_at IS NULL AND invalidated_at IS NULL;
            """, new { accountId, purpose = ChallengePurposes.EmailVerification, nowUtc }, tx, cancellationToken: cancellationToken)).ConfigureAwait(false);

        await connection.ExecuteAsync(new CommandDefinition(
            ChallengeInsert.Sql, newChallenge, tx, cancellationToken: cancellationToken)).ConfigureAwait(false);

        await connection.ExecuteAsync(new CommandDefinition(
            OutboxInsert.Sql, OutboxInsert.Params(newOutbox), tx, cancellationToken: cancellationToken)).ConfigureAwait(false);

        await tx.CommitAsync(cancellationToken).ConfigureAwait(false);
        return ResendOutcome.Replaced;
    }
}
