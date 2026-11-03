using BitosX.Application.Abstractions.Persistence;
using Dapper;
using MySqlConnector;

namespace BitosX.Infrastructure.Persistence;

/// <summary>
/// Dapper-backed <see cref="IPasskeyStore"/> over MariaDB. Timestamps are truncated to the microsecond before they
/// are written (DATETIME(6)), so what is written, returned and later read is the same value. The AAGUID is stored in
/// its RFC 4122 (big-endian) byte order, the order authenticators report it in.
/// </summary>
public sealed class PasskeyStore : IPasskeyStore
{
    private const int MySqlDuplicateKey = 1062;

    private sealed record Row(
        Guid Id, Guid AccountId, byte[] CredentialId, byte[] PublicKey, ulong SignCount, byte[] UserHandle, string Name,
        byte[] AaGuid, bool BackupEligible, bool BackedUp, string? Transports, DateTime CreatedAt, DateTime? LastUsedAt)
    {
        public StoredPasskey ToPasskey() => new(
            Id, AccountId, CredentialId, PublicKey, checked((long)SignCount), UserHandle, Name, new Guid(AaGuid, bigEndian: true),
            BackupEligible, BackedUp, Transports, CreatedAt, LastUsedAt);
    }

    private const string Columns = """
        id AS Id, account_id AS AccountId, credential_id AS CredentialId, public_key AS PublicKey, sign_count AS SignCount,
        user_handle AS UserHandle, name AS Name, aaguid AS AaGuid, backup_eligible AS BackupEligible, backed_up AS BackedUp,
        transports AS Transports, created_at AS CreatedAt, last_used_at AS LastUsedAt
        """;

    private readonly BitosxConnectionFactory _connectionFactory;

    public PasskeyStore(BitosxConnectionFactory connectionFactory)
        => _connectionFactory = connectionFactory ?? throw new ArgumentNullException(nameof(connectionFactory));

    public async Task<byte[]?> GetOrAssignUserHandleAsync(Guid accountId, byte[] candidate, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(candidate);
        if (candidate.Length != 32) throw new ArgumentException("A user handle is 32 bytes.", nameof(candidate));

        await using var connection = await _connectionFactory.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        // Assigned once: a concurrent first registration loses the conditional UPDATE and reads the winner's handle.
        // (A collision with another account's random 256-bit handle is not a practical concern; the unique key refuses it.)
        await connection.ExecuteAsync(new CommandDefinition(
            "UPDATE accounts SET webauthn_user_handle = @candidate WHERE id = @accountId AND webauthn_user_handle IS NULL;",
            new { accountId, candidate }, cancellationToken: cancellationToken)).ConfigureAwait(false);
        return await connection.QuerySingleOrDefaultAsync<byte[]?>(new CommandDefinition(
            "SELECT webauthn_user_handle FROM accounts WHERE id = @accountId;", new { accountId }, cancellationToken: cancellationToken)).ConfigureAwait(false);
    }

    public async Task<byte[]?> GetUserHandleAsync(Guid accountId, CancellationToken cancellationToken = default)
    {
        await using var connection = await _connectionFactory.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        return await connection.QuerySingleOrDefaultAsync<byte[]?>(new CommandDefinition(
            "SELECT webauthn_user_handle FROM accounts WHERE id = @accountId;", new { accountId }, cancellationToken: cancellationToken)).ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<StoredPasskey>> ListAsync(Guid accountId, CancellationToken cancellationToken = default)
    {
        await using var connection = await _connectionFactory.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        var rows = await connection.QueryAsync<Row>(new CommandDefinition(
            $"SELECT {Columns} FROM webauthn_credentials WHERE account_id = @accountId ORDER BY created_at, id;",
            new { accountId }, cancellationToken: cancellationToken)).ConfigureAwait(false);
        return rows.Select(r => r.ToPasskey()).ToList();
    }

    public async Task<int> CountAsync(Guid accountId, CancellationToken cancellationToken = default)
    {
        await using var connection = await _connectionFactory.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        return checked((int)await connection.ExecuteScalarAsync<long>(new CommandDefinition(
            "SELECT COUNT(*) FROM webauthn_credentials WHERE account_id = @accountId;", new { accountId }, cancellationToken: cancellationToken)).ConfigureAwait(false));
    }

    public async Task<StoredPasskey?> FindByCredentialIdAsync(byte[] credentialId, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(credentialId);
        if (credentialId.Length is 0 or > 1023) return null;

        await using var connection = await _connectionFactory.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        var row = await connection.QuerySingleOrDefaultAsync<Row>(new CommandDefinition(
            $"SELECT {Columns} FROM webauthn_credentials WHERE credential_id = @credentialId;",
            new { credentialId }, cancellationToken: cancellationToken)).ConfigureAwait(false);
        return row?.ToPasskey();
    }

    public async Task<bool> CredentialIdExistsAsync(byte[] credentialId, CancellationToken cancellationToken = default)
        => await FindByCredentialIdAsync(credentialId, cancellationToken).ConfigureAwait(false) is not null;

    public async Task<PasskeyInsertOutcome> InsertAsync(StoredPasskey passkey, int maxPerAccount, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(passkey);
        if (passkey.CredentialId.Length is 0 or > 1023) throw new ArgumentException("A credential id is 1..1023 bytes.", nameof(passkey));
        if (passkey.PublicKey.Length is 0 or > 2048) throw new ArgumentException("A public key is 1..2048 bytes.", nameof(passkey));
        if (passkey.UserHandle.Length != 32) throw new ArgumentException("A user handle is 32 bytes.", nameof(passkey));
        if (passkey.SignCount < 0) throw new ArgumentException("A signature counter is not negative.", nameof(passkey));

        await using var connection = await _connectionFactory.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        // READ COMMITTED + the canonical lock order accounts -> account_totp (as TOTP enrollment), then the count and
        // the insert. TOTP disable takes the account_totp lock too and counts passkeys under it, so it either sees
        // this passkey or makes the TOTP check here fail; two registrations of one account serialize on the locks.
        await using var tx = await connection.BeginTransactionAsync(System.Data.IsolationLevel.ReadCommitted, cancellationToken).ConfigureAwait(false);

        var accountExists = await connection.ExecuteScalarAsync<int?>(new CommandDefinition(
            "SELECT 1 FROM accounts WHERE id = @AccountId FOR UPDATE;", new { passkey.AccountId }, tx, cancellationToken: cancellationToken)).ConfigureAwait(false);
        var confirmed = await connection.QuerySingleOrDefaultAsync<DateTime?>(new CommandDefinition(
            "SELECT confirmed_at FROM account_totp WHERE account_id = @AccountId FOR UPDATE;", new { passkey.AccountId }, tx, cancellationToken: cancellationToken)).ConfigureAwait(false);
        if (accountExists is null || confirmed is null)
        {
            await tx.RollbackAsync(cancellationToken).ConfigureAwait(false);
            return PasskeyInsertOutcome.TwoFactorRequired;
        }

        var count = await connection.ExecuteScalarAsync<long>(new CommandDefinition(
            "SELECT COUNT(*) FROM webauthn_credentials WHERE account_id = @AccountId;", new { passkey.AccountId }, tx, cancellationToken: cancellationToken)).ConfigureAwait(false);
        if (count >= maxPerAccount)
        {
            await tx.RollbackAsync(cancellationToken).ConfigureAwait(false);
            return PasskeyInsertOutcome.LimitReached;
        }

        try
        {
            await connection.ExecuteAsync(new CommandDefinition(
                """
                INSERT INTO webauthn_credentials (id, account_id, credential_id, public_key, sign_count, user_handle, name, aaguid,
                                                  backup_eligible, backed_up, transports, created_at, last_used_at)
                VALUES (@Id, @AccountId, @CredentialId, @PublicKey, @SignCount, @UserHandle, @Name, @AaGuid,
                        @BackupEligible, @BackedUp, @Transports, @CreatedAt, NULL);
                """,
                new
                {
                    passkey.Id,
                    passkey.AccountId,
                    passkey.CredentialId,
                    passkey.PublicKey,
                    passkey.SignCount,
                    passkey.UserHandle,
                    passkey.Name,
                    AaGuid = passkey.AaGuid.ToByteArray(bigEndian: true),
                    passkey.BackupEligible,
                    passkey.BackedUp,
                    passkey.Transports,
                    CreatedAt = ToMicroseconds(passkey.CreatedAt),
                }, tx, cancellationToken: cancellationToken)).ConfigureAwait(false);
        }
        catch (MySqlException ex) when (ex.Number == MySqlDuplicateKey)
        {
            await tx.RollbackAsync(cancellationToken).ConfigureAwait(false);
            return PasskeyInsertOutcome.DuplicateCredential;
        }

        await tx.CommitAsync(cancellationToken).ConfigureAwait(false);
        return PasskeyInsertOutcome.Inserted;
    }

    public async Task<bool> RenameAsync(Guid accountId, Guid passkeyId, string name, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        await using var connection = await _connectionFactory.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        // The connection reports matched (found) rows, so renaming to the same name still answers true.
        return await connection.ExecuteAsync(new CommandDefinition(
            "UPDATE webauthn_credentials SET name = @name WHERE id = @passkeyId AND account_id = @accountId;",
            new { accountId, passkeyId, name }, cancellationToken: cancellationToken)).ConfigureAwait(false) == 1;
    }

    public async Task<bool> DeleteAsync(Guid accountId, Guid passkeyId, CancellationToken cancellationToken = default)
    {
        await using var connection = await _connectionFactory.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        return await connection.ExecuteAsync(new CommandDefinition(
            "DELETE FROM webauthn_credentials WHERE id = @passkeyId AND account_id = @accountId;",
            new { accountId, passkeyId }, cancellationToken: cancellationToken)).ConfigureAwait(false) == 1;
    }

    public async Task<bool> TryRecordUseAsync(Guid passkeyId, long expectedSignCount, long newSignCount, bool backedUp, DateTime nowUtc, CancellationToken cancellationToken = default)
    {
        if (expectedSignCount < 0 || newSignCount < 0) throw new ArgumentOutOfRangeException(nameof(newSignCount), "Signature counters are not negative.");
        await using var connection = await _connectionFactory.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        return await connection.ExecuteAsync(new CommandDefinition(
            """
            UPDATE webauthn_credentials SET sign_count = @newSignCount, backed_up = @backedUp, last_used_at = @now
            WHERE id = @passkeyId AND sign_count = @expectedSignCount;
            """, new { passkeyId, expectedSignCount, newSignCount, backedUp, now = ToMicroseconds(nowUtc) }, cancellationToken: cancellationToken)).ConfigureAwait(false) == 1;
    }

    /// <summary>DATETIME(6) keeps microseconds; truncating here makes the written value equal every later read.</summary>
    internal static DateTime ToMicroseconds(DateTime utc)
        => new(utc.Ticks - (utc.Ticks % TimeSpan.TicksPerMicrosecond), DateTimeKind.Utc);
}
