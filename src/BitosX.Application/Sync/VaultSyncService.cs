using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using BitosX.Application.Abstractions.Persistence;

namespace BitosX.Application.Sync;

/// <summary>
/// See <see cref="IVaultSyncService"/>. The only thing this class looks at inside the envelope is
/// whether it is a JSON object with a numeric <c>version</c> — the public header every BitosX vault
/// file starts with — so that garbage is refused before it takes up space. The cryptographic fields
/// are never decoded, let alone used.
/// </summary>
public sealed class VaultSyncService : IVaultSyncService
{
    private const int MaxJsonDepth = 4; // the envelope header is flat; kdfParameters is one level down

    private readonly IEnvelopeStore _store;
    private readonly VaultSyncOptions _options;

    public VaultSyncService(IEnvelopeStore store, VaultSyncOptions options)
    {
        _store = store ?? throw new ArgumentNullException(nameof(store));
        _options = options ?? throw new ArgumentNullException(nameof(options));
    }

    public Task<StoredEnvelope?> GetStatusAsync(Guid accountId, CancellationToken cancellationToken = default)
        => _store.GetAsync(accountId, includeEnvelope: false, cancellationToken);

    public Task<StoredEnvelope?> DownloadAsync(Guid accountId, CancellationToken cancellationToken = default)
        => _store.GetAsync(accountId, includeEnvelope: true, cancellationToken);

    public async Task<SyncUploadResult> UploadAsync(Guid accountId, long baseRevision, byte[] envelope, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        if (accountId == Guid.Empty) throw new ArgumentException("An account id is required.", nameof(accountId));
        if (baseRevision < 0) throw new ArgumentOutOfRangeException(nameof(baseRevision), "The base revision cannot be negative.");

        if (envelope.Length > _options.MaxEnvelopeBytes)
        {
            return new SyncUploadResult(SyncUploadOutcome.TooLarge, 0, null, envelope.Length, default);
        }

        if (!LooksLikeEnvelope(envelope))
        {
            return new SyncUploadResult(SyncUploadOutcome.InvalidEnvelope, 0, null, envelope.Length, default);
        }

        var fingerprint = SHA256.HashData(envelope);
        var result = await _store.UpsertAsync(accountId, baseRevision, envelope, fingerprint, cancellationToken).ConfigureAwait(false);
        return result.Outcome switch
        {
            EnvelopeUpsertOutcome.Stored => new SyncUploadResult(SyncUploadOutcome.Stored, result.Revision, fingerprint, envelope.Length, result.UpdatedAt),
            EnvelopeUpsertOutcome.Conflict => new SyncUploadResult(SyncUploadOutcome.Conflict, result.Revision, null, envelope.Length, result.UpdatedAt),
            _ => new SyncUploadResult(SyncUploadOutcome.NoAccount, 0, null, envelope.Length, default),
        };
    }

    public Task<bool> DeleteAsync(Guid accountId, CancellationToken cancellationToken = default)
        => _store.DeleteAsync(accountId, cancellationToken);

    /// <summary>
    /// A BitosX envelope is a UTF-8 JSON object whose top-level <c>version</c> is a positive integer.
    /// Nothing else is examined: the check guards the store against arbitrary bytes, it does not
    /// (and could not) authenticate the envelope — only the holder of the master password can.
    /// </summary>
    public static bool LooksLikeEnvelope(ReadOnlySpan<byte> envelope)
    {
        if (envelope.IsEmpty)
        {
            return false;
        }

        try
        {
            // Strict UTF-8 first: the reader would accept some malformed sequences inside strings.
            new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true).GetCharCount(envelope);

            var reader = new Utf8JsonReader(envelope, new JsonReaderOptions { MaxDepth = MaxJsonDepth, CommentHandling = JsonCommentHandling.Disallow });
            if (!reader.Read() || reader.TokenType != JsonTokenType.StartObject)
            {
                return false;
            }

            var versionSeen = false;
            while (reader.Read())
            {
                if (reader.TokenType == JsonTokenType.EndObject && reader.CurrentDepth == 0)
                {
                    break;
                }

                if (reader.TokenType == JsonTokenType.PropertyName && reader.CurrentDepth == 1 && reader.ValueTextEquals("version"u8))
                {
                    if (!reader.Read() || reader.TokenType != JsonTokenType.Number || !reader.TryGetInt32(out var version) || version < 1)
                    {
                        return false;
                    }

                    versionSeen = true;
                }
                else if (reader.TokenType is JsonTokenType.StartObject or JsonTokenType.StartArray)
                {
                    reader.Skip();
                }
            }

            // Exactly one top-level document, nothing trailing.
            return versionSeen && !reader.Read();
        }
        catch (JsonException)
        {
            return false;
        }
        catch (ArgumentException)
        {
            return false; // invalid UTF-8
        }
    }
}
