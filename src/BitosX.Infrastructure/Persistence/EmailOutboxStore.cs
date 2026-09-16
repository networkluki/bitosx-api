using BitosX.Application.Abstractions.Persistence;
using BitosX.Application.Email;
using Dapper;

namespace BitosX.Infrastructure.Persistence;

/// <summary>Dapper-backed <see cref="IEmailOutboxStore"/> over MariaDB.</summary>
public sealed class EmailOutboxStore : IEmailOutboxStore
{
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

    public async Task<int> FailAndEraseIneligibleAsync(DateTime nowUtc, CancellationToken cancellationToken = default)
    {
        await using var connection = await _connectionFactory.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        return await connection.ExecuteAsync(new CommandDefinition(
            """
            UPDATE email_outbox o
            JOIN email_verification_challenges c ON c.id = o.challenge_id
            SET o.failed_at = @nowUtc,
                o.payload_nonce = NULL, o.payload_ciphertext = NULL, o.payload_tag = NULL,
                o.locked_until = NULL, o.locked_by = NULL
            WHERE o.sent_at IS NULL AND o.failed_at IS NULL
              AND (c.consumed_at IS NOT NULL OR c.invalidated_at IS NOT NULL OR c.expires_at <= @nowUtc);
            """, new { nowUtc }, cancellationToken: cancellationToken)).ConfigureAwait(false);
    }

    public async Task<int> DeleteSanitizedOlderThanAsync(DateTime cutoffUtc, CancellationToken cancellationToken = default)
    {
        await using var connection = await _connectionFactory.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        return await connection.ExecuteAsync(new CommandDefinition(
            """
            DELETE FROM email_outbox
            WHERE (sent_at IS NOT NULL OR failed_at IS NOT NULL) AND created_at < @cutoffUtc;
            """, new { cutoffUtc }, cancellationToken: cancellationToken)).ConfigureAwait(false);
    }

    private async Task ExecuteAsync(string sql, object param, CancellationToken cancellationToken)
    {
        await using var connection = await _connectionFactory.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await connection.ExecuteAsync(new CommandDefinition(sql, param, cancellationToken: cancellationToken)).ConfigureAwait(false);
    }
}
