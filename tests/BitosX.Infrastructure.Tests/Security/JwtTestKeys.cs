using BitosX.Application.Security;

namespace BitosX.Infrastructure.Tests.Security;

/// <summary>
/// Obviously test-only, deterministic key material for JWT tests. NEVER a production
/// secret: these are fixed byte patterns Base64-encoded. Real keys are CSPRNG-generated
/// into the secret store and are never committed.
/// </summary>
internal static class JwtTestKeys
{
    /// <summary>A deterministic 32-byte Base64 key filled with <paramref name="seed"/>.</summary>
    public static string Key32(byte seed) => Convert.ToBase64String(Enumerable.Repeat(seed, 32).ToArray());

    public static readonly string CurrentKey = Key32(0x11);
    public static readonly string PreviousKey = Key32(0x22);
    public const string CurrentKid = "k1";
    public const string PreviousKid = "k2";

    /// <summary>Valid current-only options (no rotation configured).</summary>
    public static JwtOptions CurrentOnly() => new()
    {
        SigningKey = CurrentKey,
        KeyId = CurrentKid,
        Issuer = "https://api.bitosx.se",
        Audience = "bitosx-api",
        AccessTokenLifetime = TimeSpan.FromSeconds(900),
        ClockSkew = TimeSpan.FromSeconds(60),
    };

    /// <summary>Valid options with a previous key configured (rotation overlap).</summary>
    public static JwtOptions WithPrevious() => new()
    {
        SigningKey = CurrentKey,
        KeyId = CurrentKid,
        PreviousSigningKey = PreviousKey,
        PreviousKeyId = PreviousKid,
        Issuer = "https://api.bitosx.se",
        Audience = "bitosx-api",
        AccessTokenLifetime = TimeSpan.FromSeconds(900),
        ClockSkew = TimeSpan.FromSeconds(60),
    };
}
