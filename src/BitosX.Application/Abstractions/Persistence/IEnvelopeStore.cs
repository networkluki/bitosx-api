namespace BitosX.Application.Abstractions.Persistence;

/// <summary>
/// The stored encrypted envelope of an account, as the store reports it. <see cref="Envelope"/> is
/// present only when the caller asked for the bytes. Everything else is public metadata.
/// </summary>
public sealed record StoredEnvelope(
    Guid AccountId,
    long Revision,
    byte[] Fingerprint,
    int SizeBytes,
    DateTime CreatedAt,
    DateTime UpdatedAt,
    byte[]? Envelope);

public enum EnvelopeUpsertOutcome
{
    /// <summary>The envelope was stored under <see cref="EnvelopeUpsertResult.Revision"/>.</summary>
    Stored,

    /// <summary>The base revision the client named is not the current one; nothing was written.</summary>
    Conflict,

    /// <summary>The account does not exist (deleted between authentication and the write); nothing was written.</summary>
    NoAccount,
}

/// <summary>The outcome of an upsert. On <see cref="EnvelopeUpsertOutcome.Conflict"/>, <see cref="Revision"/> is the current one.</summary>
public sealed record EnvelopeUpsertResult(EnvelopeUpsertOutcome Outcome, long Revision, DateTime UpdatedAt);

/// <summary>
/// Persistence of one encrypted vault envelope per account. The store never inspects the envelope:
/// it is opaque bytes under a key the server does not have. Revisions are compare-and-set so that
/// two devices can never overwrite each other unknowingly.
/// </summary>
public interface IEnvelopeStore
{
    /// <summary>The account's stored envelope, with or without the bytes, or <see langword="null"/> when none is stored.</summary>
    Task<StoredEnvelope?> GetAsync(Guid accountId, bool includeEnvelope, CancellationToken cancellationToken = default);

    /// <summary>
    /// Stores <paramref name="envelope"/> as revision <c>baseRevision + 1</c>, if and only if the current
    /// revision is <paramref name="baseRevision"/> (0 meaning: nothing stored yet). Atomic under a row lock.
    /// </summary>
    Task<EnvelopeUpsertResult> UpsertAsync(
        Guid accountId, long baseRevision, byte[] envelope, byte[] fingerprint, CancellationToken cancellationToken = default);

    /// <summary>Removes the account's stored envelope. Idempotent; returns whether one was there.</summary>
    Task<bool> DeleteAsync(Guid accountId, CancellationToken cancellationToken = default);
}
