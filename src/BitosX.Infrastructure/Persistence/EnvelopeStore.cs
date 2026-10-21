using BitosX.Application.Abstractions.Persistence;
using Dapper;
using MySqlConnector;

namespace BitosX.Infrastructure.Persistence;

/// <summary>
/// Dapper-backed <see cref="IEnvelopeStore"/> over MariaDB (<c>vault_blobs</c>). The upsert locks the
/// account's row (or proves there is none) and compares the revision under that lock, so two devices
/// uploading at once cannot both win: one gets <see cref="EnvelopeUpsertOutcome.Conflict"/> and the
/// current revision, and writes nothing. The store never looks inside the envelope.
/// </summary>
public sealed class EnvelopeStore : IEnvelopeStore
{
    private sealed record MetaRow(Guid AccountId, long Revision, byte[] Fingerprint, int SizeBytes, DateTime CreatedAt, DateTime UpdatedAt);
    private sealed record FullRow(Guid AccountId, long Revision, byte[] Fingerprint, int SizeBytes, DateTime CreatedAt, DateTime UpdatedAt, byte[] Envelope);
    private sealed record LockRow(long Revision);

    private readonly BitosxConnectionFactory _connectionFactory;
    private readonly TimeProvider _clock;

    public EnvelopeStore(BitosxConnectionFactory connectionFactory, TimeProvider clock)
    {
        _connectionFactory = connectionFactory ?? throw new ArgumentNullException(nameof(connectionFactory));
        _clock = clock ?? throw new ArgumentNullException(nameof(clock));
    }

    public async Task<StoredEnvelope?> GetAsync(Guid accountId, bool includeEnvelope, CancellationToken cancellationToken = default)
    {
        await using var connection = await _connectionFactory.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        if (includeEnvelope)
        {
            var row = await connection.QuerySingleOrDefaultAsync<FullRow>(new CommandDefinition(
                """
                SELECT account_id, revision, fingerprint, size_bytes, created_at, updated_at, envelope
                FROM vault_blobs
                WHERE account_id = @AccountId;
                """, new { AccountId = accountId }, cancellationToken: cancellationToken)).ConfigureAwait(false);
            return row is null ? null : new StoredEnvelope(row.AccountId, row.Revision, row.Fingerprint, row.SizeBytes, row.CreatedAt, row.UpdatedAt, row.Envelope);
        }

        var meta = await connection.QuerySingleOrDefaultAsync<MetaRow>(new CommandDefinition(
            """
            SELECT account_id, revision, fingerprint, size_bytes, created_at, updated_at
            FROM vault_blobs
            WHERE account_id = @AccountId;
            """, new { AccountId = accountId }, cancellationToken: cancellationToken)).ConfigureAwait(false);
        return meta is null ? null : new StoredEnvelope(meta.AccountId, meta.Revision, meta.Fingerprint, meta.SizeBytes, meta.CreatedAt, meta.UpdatedAt, null);
    }

    public async Task<EnvelopeUpsertResult> UpsertAsync(
        Guid accountId, long baseRevision, byte[] envelope, byte[] fingerprint, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        ArgumentNullException.ThrowIfNull(fingerprint);
        if (accountId == Guid.Empty) throw new ArgumentException("An account id is required.", nameof(accountId));
        if (baseRevision < 0) throw new ArgumentOutOfRangeException(nameof(baseRevision));
        if (envelope.Length == 0) throw new ArgumentException("The envelope is empty.", nameof(envelope));
        if (fingerprint.Length != 32) throw new ArgumentException("The fingerprint must be 32 bytes.", nameof(fingerprint));

        await using var connection = await _connectionFactory.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using var tx = await connection.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);

        // The account row is locked first so a concurrent account deletion cannot slip between the
        // existence check and the write (the FK would refuse the insert, but the row lock makes the
        // ordering explicit and keeps the two uploads of one account serialized even for the first one).
        var accountExists = await connection.ExecuteScalarAsync<int?>(new CommandDefinition(
            "SELECT 1 FROM accounts WHERE id = @AccountId FOR UPDATE;",
            new { AccountId = accountId }, tx, cancellationToken: cancellationToken)).ConfigureAwait(false);
        if (accountExists is null)
        {
            await tx.RollbackAsync(cancellationToken).ConfigureAwait(false);
            return new EnvelopeUpsertResult(EnvelopeUpsertOutcome.NoAccount, 0, default);
        }

        var current = await connection.QuerySingleOrDefaultAsync<LockRow>(new CommandDefinition(
            "SELECT revision FROM vault_blobs WHERE account_id = @AccountId FOR UPDATE;",
            new { AccountId = accountId }, tx, cancellationToken: cancellationToken)).ConfigureAwait(false);

        var now = _clock.GetUtcNow().UtcDateTime;
        var currentRevision = current?.Revision ?? 0;
        if (currentRevision != baseRevision)
        {
            await tx.RollbackAsync(cancellationToken).ConfigureAwait(false);
            return new EnvelopeUpsertResult(EnvelopeUpsertOutcome.Conflict, currentRevision, now);
        }

        var nextRevision = checked(currentRevision + 1);
        int rows;
        if (current is null)
        {
            rows = await connection.ExecuteAsync(new CommandDefinition(
                """
                INSERT INTO vault_blobs (account_id, revision, size_bytes, fingerprint, envelope, created_at, updated_at)
                VALUES (@AccountId, @Revision, @SizeBytes, @Fingerprint, @Envelope, @Now, @Now);
                """,
                new { AccountId = accountId, Revision = nextRevision, SizeBytes = envelope.Length, Fingerprint = fingerprint, Envelope = envelope, Now = now },
                tx, cancellationToken: cancellationToken)).ConfigureAwait(false);
        }
        else
        {
            rows = await connection.ExecuteAsync(new CommandDefinition(
                """
                UPDATE vault_blobs
                SET revision = @Revision, size_bytes = @SizeBytes, fingerprint = @Fingerprint, envelope = @Envelope, updated_at = @Now
                WHERE account_id = @AccountId AND revision = @BaseRevision;
                """,
                new { AccountId = accountId, Revision = nextRevision, BaseRevision = baseRevision, SizeBytes = envelope.Length, Fingerprint = fingerprint, Envelope = envelope, Now = now },
                tx, cancellationToken: cancellationToken)).ConfigureAwait(false);
        }

        if (rows != 1)
        {
            await tx.RollbackAsync(cancellationToken).ConfigureAwait(false);
            throw new InvalidOperationException("The envelope write did not affect exactly one row.");
        }

        await tx.CommitAsync(cancellationToken).ConfigureAwait(false);
        return new EnvelopeUpsertResult(EnvelopeUpsertOutcome.Stored, nextRevision, now);
    }

    public async Task<bool> DeleteAsync(Guid accountId, CancellationToken cancellationToken = default)
    {
        await using var connection = await _connectionFactory.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        var rows = await connection.ExecuteAsync(new CommandDefinition(
            "DELETE FROM vault_blobs WHERE account_id = @AccountId;",
            new { AccountId = accountId }, cancellationToken: cancellationToken)).ConfigureAwait(false);
        return rows == 1;
    }
}
