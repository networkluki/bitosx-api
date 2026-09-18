namespace BitosX.Application.Security;

/// <summary>
/// Access-token (JWT) configuration. BitosX-owned plain options: this type lives in
/// the Application layer and deliberately references NO IdentityModel / JwtBearer /
/// <c>TokenValidationParameters</c> types (the inward dependency boundary). The secret
/// key material is held only in the secret store — never in Git/appsettings/MariaDB.
///
/// Key representation: <see cref="SigningKey"/> / <see cref="PreviousSigningKey"/> are
/// Base64 strings that must decode to at least 32 bytes (HS256). Key ids
/// (<see cref="KeyId"/>, <see cref="PreviousKeyId"/>) are non-secret labels compared
/// exactly (ordinal, no case-folding).
/// </summary>
public sealed class JwtOptions
{
    /// <summary>Current signing secret (Security:JwtSigningKey), Base64, ≥ 32 decoded bytes. Required.</summary>
    public string SigningKey { get; set; } = string.Empty;

    /// <summary>Current mandatory kid (Security:Jwt:KeyId), non-blank. Required.</summary>
    public string KeyId { get; set; } = string.Empty;

    /// <summary>Previous signing secret (Security:JwtPreviousSigningKey) during rotation. Paired with <see cref="PreviousKeyId"/>.</summary>
    public string? PreviousSigningKey { get; set; }

    /// <summary>Previous kid (Security:Jwt:PreviousKeyId) during rotation. Paired with <see cref="PreviousSigningKey"/>.</summary>
    public string? PreviousKeyId { get; set; }

    /// <summary>Token issuer (Security:Jwt:Issuer).</summary>
    public string Issuer { get; set; } = "https://api.bitosx.se";

    /// <summary>Token audience (Security:Jwt:Audience).</summary>
    public string Audience { get; set; } = "bitosx-api";

    /// <summary>Access-token lifetime (Security:Jwt:AccessTokenLifetimeSeconds); policy default 900 s.</summary>
    public TimeSpan AccessTokenLifetime { get; set; } = TimeSpan.FromSeconds(900);

    /// <summary>Explicit validation clock skew (Security:Jwt:ClockSkewSeconds); policy default 60 s.</summary>
    public TimeSpan ClockSkew { get; set; } = TimeSpan.FromSeconds(60);
}
