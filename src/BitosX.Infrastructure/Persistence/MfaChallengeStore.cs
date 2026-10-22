using BitosX.Application.Abstractions.Persistence;
using Dapper;

namespace BitosX.Infrastructure.Persistence;

/// <summary>Dapper-backed <see cref="IMfaChallengeStore"/> over MariaDB.</summary>
public sealed class MfaChallengeStore : IMfaChallengeStore
{
    private readonly BitosxConnectionFactory _connectionFactory;

    public MfaChallengeStore(BitosxConnectionFactory connectionFactory) => _connectionFactory = connectionFactory;

    public async Task CreateAsync(MfaChallenge challenge, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(challenge);
        if (challenge.TokenVerifier.Length != 32 || challenge.PasswordHashFingerprint.Length != 32) throw new ArgumentException("Verifier and fingerprint must be 32 bytes.", nameof(challenge));

        await using var connection = await _connectionFactory.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await connection.ExecuteAsync(new CommandDefinition(
            """
            INSERT INTO mfa_challenges (id, account_id, token_hash, password_hash_fingerprint, user_agent, created_at, expires_at, consumed_at, attempt_count)
            VALUES (@Id, @AccountId, @TokenVerifier, @PasswordHashFingerprint, @UserAgent, @CreatedAt, @ExpiresAt, NULL, 0);
            """, challenge, cancellationToken: cancellationToken)).ConfigureAwait(false);
    }

    public async Task<MfaChallengeView?> FindActiveAsync(byte[] tokenVerifier, DateTime nowUtc, CancellationToken cancellationToken = default)
    {
        await using var connection = await _connectionFactory.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        return await connection.QuerySingleOrDefaultAsync<MfaChallengeView>(new CommandDefinition(
            """
            SELECT id AS Id, account_id AS AccountId, password_hash_fingerprint AS PasswordHashFingerprint,
                   user_agent AS UserAgent, expires_at AS ExpiresAt, attempt_count AS AttemptCount
            FROM mfa_challenges
            WHERE token_hash = @tokenVerifier AND consumed_at IS NULL AND expires_at > @nowUtc;
            """, new { tokenVerifier, nowUtc }, cancellationToken: cancellationToken)).ConfigureAwait(false);
    }

    public async Task<bool> TryConsumeAsync(Guid challengeId, DateTime nowUtc, CancellationToken cancellationToken = default)
    {
        await using var connection = await _connectionFactory.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        var rows = await connection.ExecuteAsync(new CommandDefinition(
            "UPDATE mfa_challenges SET consumed_at = @nowUtc WHERE id = @challengeId AND consumed_at IS NULL AND expires_at > @nowUtc;",
            new { challengeId, nowUtc }, cancellationToken: cancellationToken)).ConfigureAwait(false);
        return rows == 1;
    }

    public async Task RecordFailedAttemptAsync(Guid challengeId, int maxAttempts, DateTime nowUtc, CancellationToken cancellationToken = default)
    {
        await using var connection = await _connectionFactory.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using var tx = await connection.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
        // Two statements, so the limit check never depends on the engine's SET evaluation order.
        await connection.ExecuteAsync(new CommandDefinition(
            "UPDATE mfa_challenges SET attempt_count = attempt_count + 1 WHERE id = @challengeId AND consumed_at IS NULL;",
            new { challengeId }, tx, cancellationToken: cancellationToken)).ConfigureAwait(false);
        await connection.ExecuteAsync(new CommandDefinition(
            "UPDATE mfa_challenges SET consumed_at = @nowUtc WHERE id = @challengeId AND consumed_at IS NULL AND attempt_count >= @maxAttempts;",
            new { challengeId, maxAttempts, nowUtc }, tx, cancellationToken: cancellationToken)).ConfigureAwait(false);
        await tx.CommitAsync(cancellationToken).ConfigureAwait(false);
    }
}
