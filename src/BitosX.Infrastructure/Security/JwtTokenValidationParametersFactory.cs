using BitosX.Application.Security;
using Microsoft.IdentityModel.Tokens;

namespace BitosX.Infrastructure.Security;

/// <summary>
/// The single authoritative source of the <see cref="TokenValidationParameters"/> used to
/// validate access tokens. Lives entirely in Infrastructure (it returns an IdentityModel type,
/// so it must not sit in the Application layer). Phase 2B's JwtBearer consumes exactly these
/// parameters — there is never a second validator.
///
/// Enforces: HS256 only; exact issuer/audience; explicit clock skew; signed tokens with an
/// expiry; and <b>mandatory kid</b> — the resolver returns exactly the one key whose id equals
/// the token's <c>kid</c> (current or, during rotation, previous). Missing/unknown/retired kid
/// resolves to no key, and the all-keys fallback is disabled, so such tokens fail closed.
/// Fails closed at construction on invalid key material.
/// </summary>
public sealed class JwtTokenValidationParametersFactory
{
    private readonly JwtOptions _options;
    private readonly JwtKeyMaterial _keys;

    public JwtTokenValidationParametersFactory(JwtOptions options)
    {
        _options = options;
        _keys = JwtKeyMaterial.FromOptions(options); // fail closed on bad key material
    }

    public TokenValidationParameters Create()
    {
        return new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = _options.Issuer,
            ValidateAudience = true,
            ValidAudience = _options.Audience,
            ValidateLifetime = true,
            RequireExpirationTime = true,
            RequireSignedTokens = true,
            ValidateIssuerSigningKey = true,
            ClockSkew = _options.ClockSkew,

            // HS256 only — reject alg=none and any other (HS384/HS512/asymmetric).
            ValidAlgorithms = [SecurityAlgorithms.HmacSha256],

            // Mandatory-kid resolution: return ONLY the key matching the token kid; never fall
            // back to trying every configured key.
            TryAllIssuerSigningKeys = false,
            IssuerSigningKey = null,
            IssuerSigningKeys = null,
            IssuerSigningKeyResolver = ResolveByKid,
        };
    }

    private IEnumerable<SecurityKey> ResolveByKid(string token, SecurityToken securityToken, string kid, TokenValidationParameters parameters)
    {
        if (string.IsNullOrEmpty(kid))
        {
            return []; // missing kid → fail closed
        }

        if (string.Equals(kid, _keys.CurrentKid, StringComparison.Ordinal))
        {
            return [_keys.CurrentKey];
        }

        if (_keys.PreviousKey is not null && _keys.PreviousKid is not null
            && string.Equals(kid, _keys.PreviousKid, StringComparison.Ordinal))
        {
            return [_keys.PreviousKey];
        }

        return []; // unknown / retired kid → fail closed (no all-keys fallback)
    }
}
