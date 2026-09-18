using BitosX.Application.Abstractions.Persistence;
using BitosX.Application.Security;

namespace BitosX.Application.Sessions;

/// <summary>
/// Application-only orchestration for session management over <see cref="ISessionStore"/>. Logout /
/// logout-all forward to the store's idempotent revocation. Listing maps raw rows to safe DTOs,
/// computing the EFFECTIVE expiry <c>min(absolute, last_seen + IdleLifetime)</c> and the current-session
/// flag, and exposing no user-agent/account-id/secret fields. Delete collapses the store outcome to a
/// coarse <see cref="DeleteSessionResult"/> (NotFound hides ownership). No DB types, no JWT crypto.
/// </summary>
public sealed class SessionManagementService : ISessionManagementService
{
    private readonly ISessionStore _sessionStore;
    private readonly RefreshTokenOptions _options;

    public SessionManagementService(ISessionStore sessionStore, RefreshTokenOptions options)
    {
        _sessionStore = sessionStore;
        _options = options;
    }

    public Task LogoutAsync(Guid accountId, Guid currentSessionId, CancellationToken cancellationToken = default)
        => _sessionStore.LogoutAsync(accountId, currentSessionId, cancellationToken);

    public Task LogoutAllAsync(Guid accountId, CancellationToken cancellationToken = default)
        => _sessionStore.LogoutAllAsync(accountId, cancellationToken);

    public async Task<IReadOnlyList<SessionListItem>> ListSessionsAsync(Guid accountId, Guid currentSessionId, CancellationToken cancellationToken = default)
    {
        var rows = await _sessionStore.ListSessionsAsync(accountId, cancellationToken).ConfigureAwait(false);
        var items = new List<SessionListItem>(rows.Count);
        foreach (var row in rows)
        {
            var idleExpiry = row.LastSeenAt + _options.IdleLifetime;
            var effectiveExpiry = idleExpiry < row.AbsoluteExpiresAt ? idleExpiry : row.AbsoluteExpiresAt;
            items.Add(new SessionListItem(row.Id, row.CreatedAt, row.LastSeenAt, effectiveExpiry, row.Id == currentSessionId));
        }

        return items;
    }

    public async Task<DeleteSessionResult> DeleteSessionAsync(Guid accountId, Guid currentSessionId, Guid targetSessionId, CancellationToken cancellationToken = default)
    {
        // Deleting the current session is allowed (effectively logout); no special restriction.
        var outcome = await _sessionStore.DeleteSessionAsync(accountId, targetSessionId, cancellationToken).ConfigureAwait(false);
        return outcome == SessionDeleteOutcome.Deleted ? DeleteSessionResult.Succeeded : DeleteSessionResult.NotFound;
    }
}
