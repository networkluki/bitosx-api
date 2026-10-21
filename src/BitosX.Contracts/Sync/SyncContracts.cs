namespace BitosX.Contracts.Sync;

/// <summary>
/// What the server holds for the account: the revision and the public fingerprint of the stored
/// encrypted envelope, never its contents (<c>GET /v1/sync/status</c>). The envelope is ciphertext the
/// server cannot read; the fingerprint is SHA-256 over those bytes, which the desktop app computes
/// over its own file to tell whether it is in step.
/// </summary>
public sealed record SyncStatusResponse(long Revision, string Fingerprint, int SizeBytes, DateTime UpdatedAt);

/// <summary>The stored envelope itself, Base64-encoded, with its metadata (<c>GET /v1/sync/envelope</c>).</summary>
public sealed record SyncEnvelopeResponse(long Revision, string Fingerprint, int SizeBytes, DateTime UpdatedAt, string Envelope);

/// <summary>
/// An upload (<c>PUT /v1/sync/envelope</c>). <see cref="BaseRevision"/> is the revision the client last
/// saw — 0 when it has never uploaded — and the server stores the envelope only if that is still the
/// current revision; otherwise it answers 409 and nothing changes. The envelope is the desktop
/// vault file, Base64-encoded: ciphertext under a key the server never has.
/// </summary>
public sealed record SyncUploadRequest(long BaseRevision, string Envelope);

/// <summary>The outcome of a stored upload: the new revision and the fingerprint the server computed.</summary>
public sealed record SyncUploadResponse(long Revision, string Fingerprint, int SizeBytes, DateTime UpdatedAt);
