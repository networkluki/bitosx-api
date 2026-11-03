using BitosX.Application.Abstractions.Persistence;
using BitosX.Application.Email;
using Dapper;

namespace BitosX.Infrastructure.Persistence;

/// <summary>Dapper-backed <see cref="IEmailOutboxStore"/> over MariaDB.</summary>
public sealed class EmailOutboxStore : IEmailOutboxStore
{
    /// <summary>Rows per statement for the sweep and the retention delete (short transactions, small lock sets).</summary>
    internal const int CleanupBatchSize = 500;

    /// <summary>Upper bound on batches per cleanup call, so one call never runs unbounded.</summary>
    internal const int MaxCleanupBatches = 20;

    private readonly BitosxConnectionFactory _connectionFactory;

    public EmailOutboxStore(BitosxConnectionFactory connectionFactory)
        => _connectionFactory = connectionFactory;

    private sealed record DueRowRaw(
        Guid Id, Guid ChallengeId, string MessageType, string RecipientEmail,
        byte PayloadVersion, byte[] PayloadNonce, byte[] PayloadCiphertext, byte[] PayloadTag,
        int AttemptCount, DateTime? ChallengeConsumedAt, DateTime? ChallengeInvalidatedAt, DateTime ChallengeExpiresAt);

    public async Task<IReadOnlyList<OutboxDueRow>> ClaimDueAsync(
        DateTime nowUtc, DateTime leaseUntil, string workerId, int batchSize, CancellationToken cancellationToken = default)
    {
        await using var connection = await _connectionFactory.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using var tx = await connection.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);

        var ids = (await connection.QueryAsync<Guid>(new CommandDefinition(
            """
            SELECT id FROM email_outbox
            WHERE sent_at IS NULL AND failed_at IS NULL AND available_at <= @nowUtc
              AND (locked_until IS NULL OR locked_until < @nowUtc)
            ORDER BY available_at
            LIMIT @batchSize
            FOR UPDATE SKIP LOCKED;
            """, new { nowUtc, batchSize }, tx, cancellationToken: cancellationToken)).ConfigureAwait(false)).AsList();

        if (ids.Count == 0)
        {
            await tx.CommitAsync(cancellationToken).ConfigureAwait(false);
            return [];
        }

        await connection.ExecuteAsync(new CommandDefinition(
            "UPDATE email_outbox SET locked_until = @leaseUntil, locked_by = @workerId WHERE id IN @ids;",
            new { leaseUntil, workerId, ids }, tx, cancellationToken: cancellationToken)).ConfigureAwait(false);

        var raws = await connection.QueryAsync<DueRowRaw>(new CommandDefinition(
            """
            SELECT o.id AS Id, o.challenge_id AS ChallengeId, o.message_type AS MessageType,
                   o.recipient_email AS RecipientEmail, o.payload_version AS PayloadVersion,
                   o.payload_nonce AS PayloadNonce, o.payload_ciphertext AS PayloadCiphertext, o.payload_tag AS PayloadTag,
                   o.attempt_count AS AttemptCount,
                   c.consumed_at AS ChallengeConsumedAt, c.invalidated_at AS ChallengeInvalidatedAt, c.expires_at AS ChallengeExpiresAt
            FROM email_outbox o
            JOIN email_verification_challenges c ON c.id = o.challenge_id
            WHERE o.id IN @ids;
            """, new { ids }, tx, cancellationToken: cancellationToken)).ConfigureAwait(false);

        await tx.CommitAsync(cancellationToken).ConfigureAwait(false);

        return raws.Select(r => new OutboxDueRow(
            r.Id, r.ChallengeId, r.MessageType, r.RecipientEmail,
            new ProtectedOutboxPayload(r.PayloadVersion, r.PayloadNonce, r.PayloadCiphertext, r.PayloadTag),
            r.AttemptCount, r.ChallengeConsumedAt, r.ChallengeInvalidatedAt, r.ChallengeExpiresAt)).ToList();
    }

    public async Task<OutboxDeliveryState?> GetDeliveryStateAsync(Guid outboxId, CancellationToken cancellationToken = default)
    {
        await using var connection = await _connectionFactory.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        return await connection.QuerySingleOrDefaultAsync<OutboxDeliveryState>(new CommandDefinition(
            """
            SELECT o.sent_at AS OutboxSentAt, o.failed_at AS OutboxFailedAt,
                   c.consumed_at AS ChallengeConsumedAt, c.invalidated_at AS ChallengeInvalidatedAt,
                   c.expires_at AS ChallengeExpiresAt
            FROM email_outbox o
            JOIN email_verification_challenges c ON c.id = o.challenge_id
            WHERE o.id = @outboxId;
            """, new { outboxId }, cancellationToken: cancellationToken)).ConfigureAwait(false);
    }

    public async Task<bool> RenewLeaseAsync(Guid id, string workerId, DateTime leaseUntil, CancellationToken cancellationToken = default)
    {
        await using var connection = await _connectionFactory.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        var rows = await connection.ExecuteAsync(new CommandDefinition(
            """
            UPDATE email_outbox SET locked_until = @leaseUntil
            WHERE id = @id AND locked_by = @workerId AND sent_at IS NULL AND failed_at IS NULL;
            """, new { id, workerId, leaseUntil }, cancellationToken: cancellationToken)).ConfigureAwait(false);
        return rows == 1;
    }

    public Task MarkSentAndErasePayloadAsync(Guid id, DateTime nowUtc, CancellationToken cancellationToken = default)
        => ExecuteAsync(
            """
            UPDATE email_outbox
            SET sent_at = @nowUtc, last_attempt_at = @nowUtc, attempt_count = attempt_count + 1,
                payload_nonce = NULL, payload_ciphertext = NULL, payload_tag = NULL,
                locked_until = NULL, locked_by = NULL
            WHERE id = @id AND sent_at IS NULL AND failed_at IS NULL;
            """, new { id, nowUtc }, cancellationToken);

    public Task MarkFailedAndErasePayloadAsync(Guid id, DateTime nowUtc, CancellationToken cancellationToken = default)
        => ExecuteAsync(
            """
            UPDATE email_outbox
            SET failed_at = @nowUtc,
                payload_nonce = NULL, payload_ciphertext = NULL, payload_tag = NULL,
                locked_until = NULL, locked_by = NULL
            WHERE id = @id AND sent_at IS NULL AND failed_at IS NULL;
            """, new { id, nowUtc }, cancellationToken);

    public Task RescheduleAsync(Guid id, DateTime availableAtUtc, DateTime nowUtc, CancellationToken cancellationToken = default)
        => ExecuteAsync(
            """
            UPDATE email_outbox
            SET attempt_count = attempt_count + 1, last_attempt_at = @nowUtc, available_at = @availableAtUtc,
                locked_until = NULL, locked_by = NULL
            WHERE id = @id AND sent_at IS NULL AND failed_at IS NULL;
            """, new { id, availableAtUtc, nowUtc }, cancellationToken);

    /// <summary>
    /// Two steps so the sweep never locks a challenge row: a plain (non-locking, consistent) read finds pending
    /// rows whose challenge is no longer active, then an UPDATE of email_outbox alone, by primary key, re-checks
    /// that each row is still non-terminal. A challenge that stopped being active never becomes active again,
    /// so the read cannot go stale in the unsafe direction. Request paths lock challenge → outbox; this path
    /// locks only outbox rows, so the two can no longer wait on each other in opposite orders.
    /// </summary>
    public async Task<int> FailAndEraseIneligibleAsync(DateTime nowUtc, CancellationToken cancellationToken = default)
    {
        await using var connection = await _connectionFactory.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        var total = 0;
        for (var batch = 0; batch < MaxCleanupBatches; batch++)
        {
            var ids = (await connection.QueryAsync<Guid>(new CommandDefinition(
                """
                SELECT o.id FROM email_outbox o
                JOIN email_verification_challenges c ON c.id = o.challenge_id
                WHERE o.sent_at IS NULL AND o.failed_at IS NULL
                  AND (c.consumed_at IS NOT NULL OR c.invalidated_at IS NOT NULL OR c.expires_at <= @nowUtc)
                LIMIT @limit;
                """, new { nowUtc, limit = CleanupBatchSize }, cancellationToken: cancellationToken)).ConfigureAwait(false)).AsList();
            if (ids.Count == 0)
            {
                break;
            }

            total += await connection.ExecuteAsync(new CommandDefinition(
                """
                UPDATE email_outbox
                SET failed_at = @nowUtc,
                    payload_nonce = NULL, payload_ciphertext = NULL, payload_tag = NULL,
                    locked_until = NULL, locked_by = NULL
                WHERE id IN @ids AND sent_at IS NULL AND failed_at IS NULL;
                """, new { nowUtc, ids }, cancellationToken: cancellationToken)).ConfigureAwait(false);

            if (ids.Count < CleanupBatchSize)
            {
                break;
            }
        }

        return total;
    }

    /// <summary>Batched by the created_at index (migration 0008): short statements, never a full-table scan.</summary>
    public async Task<int> DeleteSanitizedOlderThanAsync(DateTime cutoffUtc, CancellationToken cancellationToken = default)
    {
        await using var connection = await _connectionFactory.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        var total = 0;
        for (var batch = 0; batch < MaxCleanupBatches; batch++)
        {
            var rows = await connection.ExecuteAsync(new CommandDefinition(
                """
                DELETE FROM email_outbox
                WHERE created_at < @cutoffUtc AND (sent_at IS NOT NULL OR failed_at IS NOT NULL)
                ORDER BY created_at
                LIMIT @limit;
                """, new { cutoffUtc, limit = CleanupBatchSize }, cancellationToken: cancellationToken)).ConfigureAwait(false);
            total += rows;
            if (rows < CleanupBatchSize)
            {
                break;
            }
        }

        return total;
    }

    private async Task ExecuteAsync(string sql, object param, CancellationToken cancellationToken)
    {
        await using var connection = await _connectionFactory.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await connection.ExecuteAsync(new CommandDefinition(sql, param, cancellationToken: cancellationToken)).ConfigureAwait(false);
    }
}
