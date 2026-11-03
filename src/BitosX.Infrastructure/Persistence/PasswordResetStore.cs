using BitosX.Application.Abstractions.Persistence;
using BitosX.Application.Email;
using BitosX.Application.Verification;
using Dapper;

namespace BitosX.Infrastructure.Persistence;

/// <summary>
/// Dapper-backed <see cref="IPasswordResetStore"/> over MariaDB. Every query is bound to
/// <c>purpose = 'password_reset'</c> and to an account that can sign in (verified, password set, not
/// disabled), so an email-verification token can never reset a password and a reset token can never
/// activate an account. Lock order matches <see cref="SessionStore"/>: accounts → sessions → refresh_tokens.
/// </summary>
public sealed class PasswordResetStore : IPasswordResetStore
{
    private sealed record FinalizeRow(Guid Id, Guid AccountId, DateTime ExpiresAt);
    private sealed record ActiveOutboxRow(DateTime ChallengeCreatedAt, DateTime? SentAt, DateTime? FailedAt, DateTime? LockedUntil);

    private const string EligibleAccount =
        "a.email_verified_at IS NOT NULL AND a.password_hash IS NOT NULL AND a.disabled_at IS NULL";

    private readonly BitosxConnectionFactory _connectionFactory;
    private readonly TimeProvider _clock;

    public PasswordResetStore(BitosxConnectionFactory connectionFactory, TimeProvider clock)
    {
        _connectionFactory = connectionFactory;
        _clock = clock;
    }

    public async Task<PasswordResetIssueOutcome> IssueChallengeAsync(
        Guid accountId, EmailVerificationChallenge newChallenge, EmailOutboxMessage newOutbox,
        DateTime nowUtc, TimeSpan minReissueInterval, CancellationToken cancellationToken = default)
    {
        if (newChallenge.Purpose != ChallengePurposes.PasswordReset)
        {
            throw new ArgumentException("A password-reset challenge is required.", nameof(newChallenge));
        }

        await using var connection = await _connectionFactory.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        // READ COMMITTED: the locking read on the account's (possibly empty) challenge range takes record locks
        // only, no gap locks, so two accounts whose challenge rows are adjacent cannot deadlock on each other's
        // insert. The account row lock taken first serializes one account's issues.
        await using var tx = await connection.BeginTransactionAsync(System.Data.IsolationLevel.ReadCommitted, cancellationToken).ConfigureAwait(false);

        var eligible = await connection.QuerySingleOrDefaultAsync<Guid?>(
            new CommandDefinition(
                $"SELECT a.id FROM accounts a WHERE a.id = @accountId AND {EligibleAccount} FOR UPDATE;",
                new { accountId }, tx, cancellationToken: cancellationToken)).ConfigureAwait(false);

        if (eligible is null)
        {
            await tx.RollbackAsync(cancellationToken).ConfigureAwait(false);
            return PasswordResetIssueOutcome.AccountNotEligible;
        }

        // Lock the newest active reset challenge + its outbox row (coordinates with the dispatcher's
        // FOR UPDATE SKIP LOCKED claim exactly like resend does for verification).
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
                """, new { accountId, purpose = ChallengePurposes.PasswordReset, nowUtc }, tx, cancellationToken: cancellationToken)).ConfigureAwait(false);

        if (active is not null)
        {
            if (active.SentAt is null && active.FailedAt is null && active.LockedUntil is { } lease && lease > nowUtc)
            {
                await tx.RollbackAsync(cancellationToken).ConfigureAwait(false);
                return PasswordResetIssueOutcome.SkippedDeliveryInProgress;
            }

            if ((nowUtc - active.ChallengeCreatedAt) < minReissueInterval)
            {
                await tx.RollbackAsync(cancellationToken).ConfigureAwait(false);
                return PasswordResetIssueOutcome.SkippedTooSoon;
            }
        }

        await connection.ExecuteAsync(new CommandDefinition(
            """
            UPDATE email_verification_challenges
            SET invalidated_at = @nowUtc
            WHERE account_id = @accountId AND purpose = @purpose AND consumed_at IS NULL AND invalidated_at IS NULL;
            """, new { accountId, purpose = ChallengePurposes.PasswordReset, nowUtc }, tx, cancellationToken: cancellationToken)).ConfigureAwait(false);

        await connection.ExecuteAsync(new CommandDefinition(
            ChallengeInsert.Sql, newChallenge, tx, cancellationToken: cancellationToken)).ConfigureAwait(false);

        await connection.ExecuteAsync(new CommandDefinition(
            OutboxInsert.Sql, OutboxInsert.Params(newOutbox), tx, cancellationToken: cancellationToken)).ConfigureAwait(false);

        await tx.CommitAsync(cancellationToken).ConfigureAwait(false);
        return PasswordResetIssueOutcome.Issued;
    }

    public async Task<ActiveChallengeView?> FindActiveChallengeByVerifierAsync(
        byte[] verifierHash, DateTime nowUtc, CancellationToken cancellationToken = default)
    {
        await using var connection = await _connectionFactory.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);

        var sql =
            $"""
            SELECT c.id AS ChallengeId, c.account_id AS AccountId, c.expires_at AS ExpiresAt
            FROM email_verification_challenges c
            JOIN accounts a ON a.id = c.account_id
            WHERE c.token_hash = @verifierHash
              AND c.purpose = @purpose
              AND c.consumed_at IS NULL
              AND c.invalidated_at IS NULL
              AND c.expires_at > @nowUtc
              AND {EligibleAccount};
            """;

        return await connection.QuerySingleOrDefaultAsync<ActiveChallengeView>(
            new CommandDefinition(sql, new { verifierHash, purpose = ChallengePurposes.PasswordReset, nowUtc }, cancellationToken: cancellationToken)).ConfigureAwait(false);
    }

    public async Task<PasswordResetOutcome> FinalizeResetAsync(
        byte[] verifierHash, string passwordHashPhc, CancellationToken cancellationToken = default)
    {
        await using var connection = await _connectionFactory.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using var tx = await connection.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);

        // Lock challenge + account without an expiry predicate; expiry is decided against the
        // authoritative time read after the lock is held.
        var row = await connection.QuerySingleOrDefaultAsync<FinalizeRow>(
            new CommandDefinition(
                $"""
                SELECT c.id AS Id, c.account_id AS AccountId, c.expires_at AS ExpiresAt
                FROM email_verification_challenges c
                JOIN accounts a ON a.id = c.account_id
                WHERE c.token_hash = @verifierHash
                  AND c.purpose = @purpose
                  AND c.consumed_at IS NULL
                  AND c.invalidated_at IS NULL
                  AND {EligibleAccount}
                FOR UPDATE;
                """, new { verifierHash, purpose = ChallengePurposes.PasswordReset }, tx, cancellationToken: cancellationToken)).ConfigureAwait(false);

        if (row is null)
        {
            await tx.RollbackAsync(cancellationToken).ConfigureAwait(false);
            return PasswordResetOutcome.InvalidOrExpired;
        }

        var nowUtc = _clock.GetUtcNow().UtcDateTime;
        if (row.ExpiresAt <= nowUtc)
        {
            await tx.RollbackAsync(cancellationToken).ConfigureAwait(false);
            return PasswordResetOutcome.InvalidOrExpired;
        }

        var accountRows = await connection.ExecuteAsync(new CommandDefinition(
            """
            UPDATE accounts
            SET password_hash = @passwordHashPhc, updated_at = @nowUtc
            WHERE id = @accountId AND email_verified_at IS NOT NULL AND password_hash IS NOT NULL AND disabled_at IS NULL;
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
            return PasswordResetOutcome.InvalidOrExpired;
        }

        // Any other outstanding reset link for this account is dead once the password changed.
        await connection.ExecuteAsync(new CommandDefinition(
            """
            UPDATE email_verification_challenges
            SET invalidated_at = @nowUtc
            WHERE account_id = @accountId AND purpose = @purpose AND consumed_at IS NULL AND invalidated_at IS NULL;
            """,
            new { nowUtc, accountId = row.AccountId, purpose = ChallengePurposes.PasswordReset }, tx, cancellationToken: cancellationToken)).ConfigureAwait(false);

        // Revoke every session + refresh token (same lock order and statements as logout-all).
        var sessionIds = (await connection.QueryAsync<Guid>(new CommandDefinition(
            "SELECT id FROM sessions WHERE account_id = @accountId AND revoked_at IS NULL ORDER BY id FOR UPDATE;",
            new { accountId = row.AccountId }, tx, cancellationToken: cancellationToken)).ConfigureAwait(false)).ToList();

        if (sessionIds.Count > 0)
        {
            _ = await connection.QueryAsync<Guid>(new CommandDefinition(
                "SELECT id FROM refresh_tokens WHERE session_id IN @sessionIds ORDER BY id FOR UPDATE;",
                new { sessionIds }, tx, cancellationToken: cancellationToken)).ConfigureAwait(false);

            await connection.ExecuteAsync(new CommandDefinition(
                "UPDATE sessions SET revoked_at = @nowUtc WHERE account_id = @accountId AND revoked_at IS NULL;",
                new { nowUtc, accountId = row.AccountId }, tx, cancellationToken: cancellationToken)).ConfigureAwait(false);
            await connection.ExecuteAsync(new CommandDefinition(
                "UPDATE refresh_tokens SET revoked_at = @nowUtc WHERE session_id IN @sessionIds AND revoked_at IS NULL;",
                new { nowUtc, sessionIds }, tx, cancellationToken: cancellationToken)).ConfigureAwait(false);
        }

        await tx.CommitAsync(cancellationToken).ConfigureAwait(false);
        return PasswordResetOutcome.Reset;
    }
}
