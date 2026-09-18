using BitosX.Application.Security;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace BitosX.Infrastructure.Security;

/// <summary>
/// Issuance-only access-token service. Signs HS256 JWTs with the CURRENT key only and
/// stamps the current mandatory <c>kid</c> in the header. Fails closed at construction on
/// invalid key material (see <see cref="JwtKeyMaterial"/>). Claims are minimal
/// (<c>sub, sid, jti, iat, exp, iss, aud</c>, plus <c>nbf</c>); no email/phone/role/vault
/// data ever appears. Tokens are never persisted or logged.
/// </summary>
public sealed class JwtAccessTokenService : IAccessTokenService
{
    private readonly JwtOptions _options;
    private readonly SigningCredentials _signingCredentials;
    private readonly JsonWebTokenHandler _handler = new();

    public JwtAccessTokenService(JwtOptions options)
    {
        _options = options;
        var keys = JwtKeyMaterial.FromOptions(options); // fail closed on bad key material
        _signingCredentials = new SigningCredentials(keys.CurrentKey, SecurityAlgorithms.HmacSha256);
    }

    public AccessToken Issue(Guid accountId, Guid sessionId, DateTime nowUtc)
    {
        var now = nowUtc.Kind == DateTimeKind.Utc ? nowUtc : nowUtc.ToUniversalTime();
        var expiresAt = now + _options.AccessTokenLifetime;
        var jti = Guid.NewGuid();

        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = _options.Issuer,
            Audience = _options.Audience,
            IssuedAt = now,
            NotBefore = now,
            Expires = expiresAt,
            Claims = new Dictionary<string, object>
            {
                ["sub"] = accountId.ToString(),
                ["sid"] = sessionId.ToString(),
                ["jti"] = jti.ToString(),
            },
            SigningCredentials = _signingCredentials,
        };

        var token = _handler.CreateToken(descriptor);
        return new AccessToken(token, expiresAt, jti);
    }
}
