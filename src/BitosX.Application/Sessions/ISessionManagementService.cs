namespace BitosX.Application.Sessions;

/// <summary>
/// A privacy-conscious session summary for listing. Contains NO raw user-agent, account id, email,
/// phone, token, hash, or vault field. <see cref="ExpiresAt"/> is the session's EFFECTIVE expiry:
/// <c>min(absolute_expires_at, last_seen_at + IdleLifetime)</c> — the point at which the session
/// stops authorizing (whichever of the absolute cap or the idle window comes first). <see cref="Current"/>
/// marks the caller's own session.
/// </summary>
public sealed record SessionListItem(Guid Id, DateTime CreatedAt, DateTime LastSeenAt, DateTime ExpiresAt, bool Current);

/// <summary>Coarse delete outcome — <see cref="NotFound"/> hides ownership (never reveals another account's session).</summary>
public enum DeleteSessionResult
{
    Succeeded,
    NotFound,
}

/// <summary>
/// Application-only orchestration for session management: logout (revoke current), logout-all,
/// list, and delete/revoke an owned session. No DB types, no JWT crypto, no HTTP status codes.
/// </summary>
public interface ISessionManagementService
{
    Task LogoutAsync(Guid accountId, Guid currentSessionId, CancellationToken cancellationToken = default);

    Task LogoutAllAsync(Guid accountId, CancellationToken cancellationToken = default);

    Task<IReadOnlyList<SessionListItem>> ListSessionsAsync(Guid accountId, Guid currentSessionId, CancellationToken cancellationToken = default);

    Task<DeleteSessionResult> DeleteSessionAsync(Guid accountId, Guid currentSessionId, Guid targetSessionId, CancellationToken cancellationToken = default);
}
