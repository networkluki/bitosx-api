namespace BitosX.Application.Security;

/// <summary>A freshly issued access token and its non-secret metadata. BitosX-owned model.</summary>
/// <param name="Token">The signed compact JWT string (returned to the caller; never persisted, never logged).</param>
/// <param name="ExpiresAt">UTC expiry (issued-at + configured lifetime).</param>
/// <param name="Jti">The token's unique id claim value.</param>
public sealed record AccessToken(string Token, DateTime ExpiresAt, Guid Jti);

/// <summary>
/// Issues access JWTs. <b>Issuance-only</b> — request-path validation is owned by
/// ASP.NET Core JwtBearer (Phase 2B), configured from the single Infrastructure
/// validation-parameters factory. This contract intentionally uses only BitosX-owned
/// primitive/model types so the Application layer takes no IdentityModel dependency.
/// </summary>
public interface IAccessTokenService
{
    /// <summary>Mints a signed access token for the given account + session at <paramref name="nowUtc"/>.</summary>
    AccessToken Issue(Guid accountId, Guid sessionId, DateTime nowUtc);
}
