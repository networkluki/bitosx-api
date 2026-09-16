using BitosX.Application.Email;

namespace BitosX.Application.Abstractions.Persistence;

/// <summary>
/// A leased due outbox row joined to its challenge's authoritative state, so the
/// dispatcher can check eligibility BEFORE decrypting the payload.
/// </summary>
public sealed record OutboxDueRow(
    Guid Id,
    Guid ChallengeId,
    string MessageType,
    string RecipientEmail,
    ProtectedOutboxPayload Payload,
    DateTime? ChallengeConsumedAt,
    DateTime? ChallengeInvalidatedAt,
    DateTime ChallengeExpiresAt);

/// <summary>Durable email outbox operations (dispatcher-facing).</summary>
public interface IEmailOutboxStore
{
    /// <summary>Atomically leases up to <paramref name="batchSize"/> due rows for this worker.</summary>
    Task<IReadOnlyList<OutboxDueRow>> ClaimDueAsync(
        DateTime nowUtc, DateTime leaseUntil, string workerId, int batchSize, CancellationToken cancellationToken = default);

    /// <summary>Marks sent and erases the encrypted payload columns; clears the lease.</summary>
    Task MarkSentAndErasePayloadAsync(Guid id, DateTime nowUtc, CancellationToken cancellationToken = default);

    /// <summary>Marks permanently failed/expired and erases the payload; clears the lease.</summary>
    Task MarkFailedAndErasePayloadAsync(Guid id, DateTime nowUtc, CancellationToken cancellationToken = default);

    /// <summary>Records a transient failure and schedules the next attempt; releases the lease.</summary>
    Task RescheduleAsync(Guid id, DateTime availableAtUtc, DateTime nowUtc, CancellationToken cancellationToken = default);

    /// <summary>Marks-failed + erases payloads of unsent rows whose challenge is no longer active (≤24h cleanup).</summary>
    Task<int> FailAndEraseIneligibleAsync(DateTime nowUtc, CancellationToken cancellationToken = default);

    /// <summary>Deletes terminal (sent/failed) rows older than the cutoff (metadata retention).</summary>
    Task<int> DeleteSanitizedOlderThanAsync(DateTime cutoffUtc, CancellationToken cancellationToken = default);
}
