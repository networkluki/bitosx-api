namespace BitosX.Application.Sessions;

/// <summary>Coarse per-request authorization outcome — no reason detail is exposed.</summary>
public enum SessionAuthResult
{
    Valid,
    Invalid,
}

/// <summary>
/// Per-request session-state authorization. This is NOT a JwtBearer handler, JWT parser, signature
/// validator, or HTTP component — it receives already-validated BitosX-owned identifiers
/// (<c>accountId</c>, <c>sessionId</c> extracted from a verified JWT elsewhere) and checks the
/// authoritative session/account state. The check is READ-ONLY and never updates <c>last_seen_at</c>
/// (only refresh does). Application-only; no IdentityModel/JwtBearer dependency.
/// </summary>
public interface ISessionAuthenticator
{
    Task<SessionAuthResult> AuthenticateAsync(Guid accountId, Guid sessionId, CancellationToken cancellationToken = default);
}
