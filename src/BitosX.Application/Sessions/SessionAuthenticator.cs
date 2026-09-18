using BitosX.Application.Abstractions.Persistence;
using BitosX.Application.Security;

namespace BitosX.Application.Sessions;

/// <summary>
/// Per-request session-state authorization over the read-only <see cref="ISessionStore"/> auth
/// lookup. Reads one authoritative <see cref="SessionAuthState"/> and requires: it exists; the
/// authoritative owner equals the claimed account; the session id matches; the session is not
/// revoked; the account is not disabled; the absolute expiry is in the future; and the idle window
/// (now − last_seen) is under <see cref="RefreshTokenOptions.IdleLifetime"/>. Any failure → coarse
/// <see cref="SessionAuthResult.Invalid"/>. READ-ONLY — never updates last_seen_at. One authoritative
/// <c>now</c> per check.
/// </summary>
public sealed class SessionAuthenticator : ISessionAuthenticator
{
    private readonly ISessionStore _sessionStore;
    private readonly TimeProvider _clock;
    private readonly RefreshTokenOptions _options;

    public SessionAuthenticator(ISessionStore sessionStore, TimeProvider clock, RefreshTokenOptions options)
    {
        _sessionStore = sessionStore;
        _clock = clock;
        _options = options;
    }

    public async Task<SessionAuthResult> AuthenticateAsync(Guid accountId, Guid sessionId, CancellationToken cancellationToken = default)
    {
        var state = await _sessionStore.GetSessionAuthStateAsync(sessionId, cancellationToken).ConfigureAwait(false);
        if (state is null)
        {
            return SessionAuthResult.Invalid;
        }

        var now = _clock.GetUtcNow().UtcDateTime;

        var valid = state.AccountId == accountId
            && state.SessionId == sessionId
            && state.RevokedAt is null
            && state.AccountDisabledAt is null
            && state.AbsoluteExpiresAt > now
            && (now - state.LastSeenAt) < _options.IdleLifetime;

        return valid ? SessionAuthResult.Valid : SessionAuthResult.Invalid;
    }
}
