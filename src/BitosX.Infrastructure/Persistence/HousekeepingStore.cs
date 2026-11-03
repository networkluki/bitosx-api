using BitosX.Application.Abstractions.Persistence;
using Dapper;

namespace BitosX.Infrastructure.Persistence;

/// <summary>
/// Dapper-backed <see cref="IHousekeepingStore"/> over MariaDB. Every delete is a single bounded statement over
/// an index added by migration 0008 (<c>ORDER BY … LIMIT</c>), so it never scans or locks a whole table. Rows
/// are dead long before they are touched here (the cutoff is the retention window), so no request path still
/// uses them. Deleting a session cascades its refresh tokens (sessions → refresh_tokens, the canonical order);
/// deleting a challenge cascades its outbox row (challenge → outbox, the order the request paths use).
/// </summary>
public sealed class HousekeepingStore : IHousekeepingStore
{
    private readonly BitosxConnectionFactory _connectionFactory;

    public HousekeepingStore(BitosxConnectionFactory connectionFactory)
        => _connectionFactory = connectionFactory ?? throw new ArgumentNullException(nameof(connectionFactory));

    public async Task<int> DeleteExpiredEmailChallengesAsync(DateTime cutoffUtc, int batchSize, CancellationToken cancellationToken = default)
    {
        await using var connection = await _connectionFactory.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        return await connection.ExecuteAsync(new CommandDefinition(
            "DELETE FROM email_verification_challenges WHERE expires_at < @cutoffUtc ORDER BY expires_at LIMIT @batchSize;",
            new { cutoffUtc, batchSize }, cancellationToken: cancellationToken)).ConfigureAwait(false);
    }

    public async Task<int> DeleteExpiredMfaChallengesAsync(DateTime cutoffUtc, int batchSize, CancellationToken cancellationToken = default)
    {
        await using var connection = await _connectionFactory.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        return await connection.ExecuteAsync(new CommandDefinition(
            "DELETE FROM mfa_challenges WHERE expires_at < @cutoffUtc ORDER BY expires_at LIMIT @batchSize;",
            new { cutoffUtc, batchSize }, cancellationToken: cancellationToken)).ConfigureAwait(false);
    }

    public async Task<int> DeleteExpiredWebAuthnChallengesAsync(DateTime cutoffUtc, int batchSize, CancellationToken cancellationToken = default)
    {
        await using var connection = await _connectionFactory.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        return await connection.ExecuteAsync(new CommandDefinition(
            "DELETE FROM webauthn_challenges WHERE expires_at < @cutoffUtc ORDER BY expires_at LIMIT @batchSize;",
            new { cutoffUtc, batchSize }, cancellationToken: cancellationToken)).ConfigureAwait(false);
    }

    public async Task<int> DeleteDeadSessionsAsync(DateTime cutoffUtc, DateTime idleCutoffUtc, int batchSize, CancellationToken cancellationToken = default)
    {
        await using var connection = await _connectionFactory.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);

        // One indexed range per way a session dies; each branch is bounded, the union is at most 3 × batchSize.
        var ids = (await connection.QueryAsync<Guid>(new CommandDefinition(
            """
            (SELECT id FROM sessions WHERE revoked_at < @cutoffUtc ORDER BY revoked_at LIMIT @batchSize)
            UNION
            (SELECT id FROM sessions WHERE absolute_expires_at < @cutoffUtc ORDER BY absolute_expires_at LIMIT @batchSize)
            UNION
            (SELECT id FROM sessions WHERE last_seen_at < @idleCutoffUtc ORDER BY last_seen_at LIMIT @batchSize);
            """, new { cutoffUtc, idleCutoffUtc, batchSize }, cancellationToken: cancellationToken)).ConfigureAwait(false))
            .Take(batchSize)
            .ToList();
        if (ids.Count == 0)
        {
            return 0;
        }

        // Re-check the predicate in the DELETE itself (by primary key), so nothing that came back to life is removed.
        return await connection.ExecuteAsync(new CommandDefinition(
            """
            DELETE FROM sessions
            WHERE id IN @ids AND (revoked_at < @cutoffUtc OR absolute_expires_at < @cutoffUtc OR last_seen_at < @idleCutoffUtc);
            """, new { ids, cutoffUtc, idleCutoffUtc }, cancellationToken: cancellationToken)).ConfigureAwait(false);
    }
}
