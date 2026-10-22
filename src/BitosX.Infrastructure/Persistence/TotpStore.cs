using BitosX.Application.Abstractions.Persistence;
using BitosX.Application.Mfa;
using Dapper;

namespace BitosX.Infrastructure.Persistence;

/// <summary>Dapper-backed <see cref="ITotpStore"/> over MariaDB. Replay and single-use decisions are conditional UPDATEs (affected = 1).</summary>
public sealed class TotpStore : ITotpStore
{
    private sealed record Row(Guid AccountId, byte SecretVersion, byte[] SecretNonce, byte[] SecretCiphertext, byte[] SecretTag, DateTime CreatedAt, DateTime? ConfirmedAt, long? LastUsedStep);

    private readonly BitosxConnectionFactory _connectionFactory;

    public TotpStore(BitosxConnectionFactory connectionFactory) => _connectionFactory = connectionFactory;

    public async Task<TotpEnrollment?> GetAsync(Guid accountId, CancellationToken cancellationToken = default)
    {
        await using var connection = await _connectionFactory.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        var row = await connection.QuerySingleOrDefaultAsync<Row>(new CommandDefinition(
            """
            SELECT account_id AS AccountId, secret_version AS SecretVersion, secret_nonce AS SecretNonce,
                   secret_ciphertext AS SecretCiphertext, secret_tag AS SecretTag, created_at AS CreatedAt,
                   confirmed_at AS ConfirmedAt, last_used_step AS LastUsedStep
            FROM account_totp WHERE account_id = @accountId;
            """, new { accountId }, cancellationToken: cancellationToken)).ConfigureAwait(false);
        return row is null ? null : new TotpEnrollment(row.AccountId,
            new ProtectedTotpSecret(row.SecretVersion, row.SecretNonce, row.SecretCiphertext, row.SecretTag), row.CreatedAt, row.ConfirmedAt, row.LastUsedStep);
    }

    public async Task<TotpPendingOutcome> StorePendingAsync(Guid accountId, ProtectedTotpSecret secret, DateTime nowUtc, CancellationToken cancellationToken = default)
    {
        await using var connection = await _connectionFactory.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using var tx = await connection.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);

        var confirmed = await connection.QuerySingleOrDefaultAsync<DateTime?>(new CommandDefinition(
            "SELECT confirmed_at FROM account_totp WHERE account_id = @accountId FOR UPDATE;", new { accountId }, tx, cancellationToken: cancellationToken)).ConfigureAwait(false);
        var exists = await connection.ExecuteScalarAsync<long>(new CommandDefinition(
            "SELECT COUNT(*) FROM account_totp WHERE account_id = @accountId;", new { accountId }, tx, cancellationToken: cancellationToken)).ConfigureAwait(false) == 1;
        if (exists && confirmed is not null)
        {
            await tx.RollbackAsync(cancellationToken).ConfigureAwait(false);
            return TotpPendingOutcome.AlreadyConfirmed;
        }

        var p = new { accountId, secret.Version, secret.Nonce, secret.Ciphertext, secret.Tag, nowUtc };
        if (exists)
        {
            await connection.ExecuteAsync(new CommandDefinition(
                """
                UPDATE account_totp SET secret_version = @Version, secret_nonce = @Nonce, secret_ciphertext = @Ciphertext,
                       secret_tag = @Tag, created_at = @nowUtc, confirmed_at = NULL, last_used_step = NULL
                WHERE account_id = @accountId AND confirmed_at IS NULL;
                """, p, tx, cancellationToken: cancellationToken)).ConfigureAwait(false);
        }
        else
        {
            await connection.ExecuteAsync(new CommandDefinition(
                """
                INSERT INTO account_totp (account_id, secret_version, secret_nonce, secret_ciphertext, secret_tag, created_at, confirmed_at, last_used_step)
                VALUES (@accountId, @Version, @Nonce, @Ciphertext, @Tag, @nowUtc, NULL, NULL);
                """, p, tx, cancellationToken: cancellationToken)).ConfigureAwait(false);
        }

        await tx.CommitAsync(cancellationToken).ConfigureAwait(false);
        return TotpPendingOutcome.Stored;
    }

    public async Task<TotpConfirmOutcome> ConfirmAsync(Guid accountId, long usedStep, IReadOnlyList<byte[]> recoveryCodeVerifiers, DateTime nowUtc, CancellationToken cancellationToken = default)
    {
        await using var connection = await _connectionFactory.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using var tx = await connection.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);

        var rows = await connection.ExecuteAsync(new CommandDefinition(
            "UPDATE account_totp SET confirmed_at = @nowUtc, last_used_step = @usedStep WHERE account_id = @accountId AND confirmed_at IS NULL;",
            new { accountId, usedStep, nowUtc }, tx, cancellationToken: cancellationToken)).ConfigureAwait(false);
        if (rows != 1)
        {
            await tx.RollbackAsync(cancellationToken).ConfigureAwait(false);
            return TotpConfirmOutcome.NotPending;
        }

        await WriteRecoveryCodesAsync(connection, tx, accountId, recoveryCodeVerifiers, nowUtc, cancellationToken).ConfigureAwait(false);
        await tx.CommitAsync(cancellationToken).ConfigureAwait(false);
        return TotpConfirmOutcome.Confirmed;
    }

    public async Task<bool> TryConsumeStepAsync(Guid accountId, long step, CancellationToken cancellationToken = default)
    {
        await using var connection = await _connectionFactory.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        var rows = await connection.ExecuteAsync(new CommandDefinition(
            """
            UPDATE account_totp SET last_used_step = @step
            WHERE account_id = @accountId AND confirmed_at IS NOT NULL AND (last_used_step IS NULL OR last_used_step < @step);
            """, new { accountId, step }, cancellationToken: cancellationToken)).ConfigureAwait(false);
        return rows == 1;
    }

    public async Task<bool> TryConsumeRecoveryCodeAsync(Guid accountId, byte[] verifier, DateTime nowUtc, CancellationToken cancellationToken = default)
    {
        await using var connection = await _connectionFactory.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        var rows = await connection.ExecuteAsync(new CommandDefinition(
            "UPDATE account_recovery_codes SET used_at = @nowUtc WHERE account_id = @accountId AND code_hash = @verifier AND used_at IS NULL;",
            new { accountId, verifier, nowUtc }, cancellationToken: cancellationToken)).ConfigureAwait(false);
        return rows == 1;
    }

    public async Task<int> CountUnusedRecoveryCodesAsync(Guid accountId, CancellationToken cancellationToken = default)
    {
        await using var connection = await _connectionFactory.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        return await connection.ExecuteScalarAsync<int>(new CommandDefinition(
            "SELECT COUNT(*) FROM account_recovery_codes WHERE account_id = @accountId AND used_at IS NULL;",
            new { accountId }, cancellationToken: cancellationToken)).ConfigureAwait(false);
    }

    public async Task<bool> ReplaceRecoveryCodesAsync(Guid accountId, IReadOnlyList<byte[]> recoveryCodeVerifiers, DateTime nowUtc, CancellationToken cancellationToken = default)
    {
        await using var connection = await _connectionFactory.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using var tx = await connection.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);

        var confirmed = await connection.ExecuteScalarAsync<long>(new CommandDefinition(
            "SELECT COUNT(*) FROM account_totp WHERE account_id = @accountId AND confirmed_at IS NOT NULL FOR UPDATE;",
            new { accountId }, tx, cancellationToken: cancellationToken)).ConfigureAwait(false) == 1;
        if (!confirmed)
        {
            await tx.RollbackAsync(cancellationToken).ConfigureAwait(false);
            return false;
        }

        await WriteRecoveryCodesAsync(connection, tx, accountId, recoveryCodeVerifiers, nowUtc, cancellationToken).ConfigureAwait(false);
        await tx.CommitAsync(cancellationToken).ConfigureAwait(false);
        return true;
    }

    public async Task DisableAsync(Guid accountId, CancellationToken cancellationToken = default)
    {
        await using var connection = await _connectionFactory.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using var tx = await connection.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
        await connection.ExecuteAsync(new CommandDefinition("DELETE FROM account_recovery_codes WHERE account_id = @accountId;", new { accountId }, tx, cancellationToken: cancellationToken)).ConfigureAwait(false);
        await connection.ExecuteAsync(new CommandDefinition("DELETE FROM mfa_challenges WHERE account_id = @accountId;", new { accountId }, tx, cancellationToken: cancellationToken)).ConfigureAwait(false);
        await connection.ExecuteAsync(new CommandDefinition("DELETE FROM account_totp WHERE account_id = @accountId;", new { accountId }, tx, cancellationToken: cancellationToken)).ConfigureAwait(false);
        await tx.CommitAsync(cancellationToken).ConfigureAwait(false);
    }

    private static async Task WriteRecoveryCodesAsync(
        System.Data.Common.DbConnection connection, System.Data.Common.DbTransaction tx, Guid accountId,
        IReadOnlyList<byte[]> verifiers, DateTime nowUtc, CancellationToken cancellationToken)
    {
        await connection.ExecuteAsync(new CommandDefinition(
            "DELETE FROM account_recovery_codes WHERE account_id = @accountId;", new { accountId }, tx, cancellationToken: cancellationToken)).ConfigureAwait(false);
        foreach (var verifier in verifiers)
        {
            await connection.ExecuteAsync(new CommandDefinition(
                "INSERT INTO account_recovery_codes (id, account_id, code_hash, created_at, used_at) VALUES (@Id, @accountId, @verifier, @nowUtc, NULL);",
                new { Id = Guid.NewGuid(), accountId, verifier, nowUtc }, tx, cancellationToken: cancellationToken)).ConfigureAwait(false);
        }
    }
}
