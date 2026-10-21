using BitosX.Application.Abstractions.Persistence;

namespace BitosX.Application.Sync;

public enum SyncUploadOutcome
{
    Stored,

    /// <summary>The server holds a revision the client has not seen; nothing was written.</summary>
    Conflict,

    /// <summary>Not a BitosX envelope: not UTF-8 JSON, not an object, no <c>version</c>, or empty.</summary>
    InvalidEnvelope,

    /// <summary>Larger than <see cref="VaultSyncOptions.MaxEnvelopeBytes"/>.</summary>
    TooLarge,

    /// <summary>The account no longer exists.</summary>
    NoAccount,
}

/// <summary>The outcome of an upload; on <see cref="SyncUploadOutcome.Conflict"/> the server's current revision.</summary>
public sealed record SyncUploadResult(SyncUploadOutcome Outcome, long Revision, byte[]? Fingerprint, int SizeBytes, DateTime UpdatedAt);

/// <summary>
/// Encrypted-envelope sync for a signed-in account. The server is zero-knowledge here by construction:
/// the envelope is stored and returned as the bytes the client sent, after a cheap shape check that
/// reads only the public header, and its fingerprint is computed over those bytes. No key, no
/// password, no plaintext is ever involved.
/// </summary>
public interface IVaultSyncService
{
    Task<StoredEnvelope?> GetStatusAsync(Guid accountId, CancellationToken cancellationToken = default);

    Task<StoredEnvelope?> DownloadAsync(Guid accountId, CancellationToken cancellationToken = default);

    Task<SyncUploadResult> UploadAsync(Guid accountId, long baseRevision, byte[] envelope, CancellationToken cancellationToken = default);

    Task<bool> DeleteAsync(Guid accountId, CancellationToken cancellationToken = default);
}
