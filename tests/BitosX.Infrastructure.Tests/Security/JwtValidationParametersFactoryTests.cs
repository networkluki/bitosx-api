using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using BitosX.Application.Security;
using BitosX.Infrastructure.Security;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace BitosX.Infrastructure.Tests.Security;

/// <summary>
/// The single shared validation-parameters factory (Infrastructure). Tokens are hand-crafted
/// so each test isolates exactly one dimension (kid / alg / key / issuer / audience / expiry).
/// Validation is run through JsonWebTokenHandler against the factory-produced parameters — the
/// same parameters JwtBearer will consume in 2B — never a bespoke test validator.
/// </summary>
public sealed class JwtValidationParametersFactoryTests
{
    private static long Unix(DateTime utc) => new DateTimeOffset(utc, TimeSpan.Zero).ToUnixTimeSeconds();

    private static string B64Url(byte[] b) => Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    /// <summary>Hand-crafts a compact JWS with full control over header (kid/alg) and signing key.</summary>
    private static string Sign(byte[] key, string alg, string? kid,
        string iss = "https://api.bitosx.se", string aud = "bitosx-api",
        DateTime? expUtc = null, DateTime? iatUtc = null)
    {
        var now = DateTime.UtcNow;
        var header = new Dictionary<string, object> { ["alg"] = alg, ["typ"] = "JWT" };
        if (kid is not null) header["kid"] = kid;
        var payload = new Dictionary<string, object>
        {
            ["iss"] = iss,
            ["aud"] = aud,
            ["sub"] = Guid.NewGuid().ToString(),
            ["sid"] = Guid.NewGuid().ToString(),
            ["jti"] = Guid.NewGuid().ToString(),
            ["iat"] = Unix(iatUtc ?? now),
            ["exp"] = Unix(expUtc ?? now.AddSeconds(900)),
        };
        var h = B64Url(JsonSerializer.SerializeToUtf8Bytes(header));
        var p = B64Url(JsonSerializer.SerializeToUtf8Bytes(payload));
        var signingInput = $"{h}.{p}";
        var sig = alg switch
        {
            "HS256" => new HMACSHA256(key).ComputeHash(Encoding.ASCII.GetBytes(signingInput)),
            "HS384" => new HMACSHA384(key).ComputeHash(Encoding.ASCII.GetBytes(signingInput)),
            "HS512" => new HMACSHA512(key).ComputeHash(Encoding.ASCII.GetBytes(signingInput)),
            "none" => [],
            _ => throw new ArgumentOutOfRangeException(nameof(alg)),
        };
        return alg == "none" ? $"{signingInput}." : $"{signingInput}.{B64Url(sig)}";
    }

    private static byte[] CurrentBytes => Convert.FromBase64String(JwtTestKeys.CurrentKey);
    private static byte[] PreviousBytes => Convert.FromBase64String(JwtTestKeys.PreviousKey);

    private static async Task<bool> IsValid(JwtOptions options, string token)
    {
        var parameters = new JwtTokenValidationParametersFactory(options).Create();
        var result = await new JsonWebTokenHandler().ValidateTokenAsync(token, parameters);
        return result.IsValid;
    }

    // ---- kid resolution ----

    [Fact]
    public async Task CurrentKid_SelectsCurrentKeyOnly_Valid()
        => Assert.True(await IsValid(JwtTestKeys.WithPrevious(), Sign(CurrentBytes, "HS256", JwtTestKeys.CurrentKid)));

    [Fact]
    public async Task PreviousKid_SelectsPreviousKeyOnly_Valid()
        => Assert.True(await IsValid(JwtTestKeys.WithPrevious(), Sign(PreviousBytes, "HS256", JwtTestKeys.PreviousKid)));

    [Fact]
    public async Task MissingKid_Rejected()
        => Assert.False(await IsValid(JwtTestKeys.CurrentOnly(), Sign(CurrentBytes, "HS256", kid: null)));

    [Fact]
    public async Task UnknownKid_Rejected()
        => Assert.False(await IsValid(JwtTestKeys.CurrentOnly(), Sign(CurrentBytes, "HS256", "k99")));

    [Fact]
    public async Task RetiredPreviousKid_Rejected()
    {
        // Signed validly under the previous key/kid, but the factory has NO previous configured (retired).
        var token = Sign(PreviousBytes, "HS256", JwtTestKeys.PreviousKid);
        Assert.False(await IsValid(JwtTestKeys.CurrentOnly(), token));
    }

    [Fact]
    public async Task NoAllKeysFallback_UnknownKidSignedWithConfiguredKey_Rejected()
    {
        // Signature WOULD verify against the current key, but kid is unknown → resolver yields
        // no key and there must be no fallback to trying every configured key.
        Assert.False(await IsValid(JwtTestKeys.WithPrevious(), Sign(CurrentBytes, "HS256", "k99")));
    }

    [Fact]
    public async Task NoAllKeysFallback_CurrentKidButSignedWithPreviousKey_Rejected()
    {
        // kid=current resolves ONLY the current key; a signature made with the previous key must fail.
        Assert.False(await IsValid(JwtTestKeys.WithPrevious(), Sign(PreviousBytes, "HS256", JwtTestKeys.CurrentKid)));
    }

    // ---- algorithm restriction ----

    [Fact]
    public async Task AlgNone_Rejected()
        => Assert.False(await IsValid(JwtTestKeys.CurrentOnly(), Sign(CurrentBytes, "none", JwtTestKeys.CurrentKid)));

    [Fact]
    public async Task Hs384_Rejected()
        => Assert.False(await IsValid(JwtTestKeys.CurrentOnly(), Sign(CurrentBytes, "HS384", JwtTestKeys.CurrentKid)));

    [Fact]
    public async Task Hs512_Rejected()
        => Assert.False(await IsValid(JwtTestKeys.CurrentOnly(), Sign(CurrentBytes, "HS512", JwtTestKeys.CurrentKid)));

    [Fact]
    public async Task AsymmetricRs256_Rejected()
    {
        using var rsa = RSA.Create(2048);
        var key = new RsaSecurityKey(rsa) { KeyId = JwtTestKeys.CurrentKid };
        var now = DateTime.UtcNow;
        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = "https://api.bitosx.se",
            Audience = "bitosx-api",
            IssuedAt = now,
            NotBefore = now,
            Expires = now.AddSeconds(900),
            Claims = new Dictionary<string, object> { ["sub"] = Guid.NewGuid().ToString(), ["sid"] = Guid.NewGuid().ToString(), ["jti"] = Guid.NewGuid().ToString() },
            SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.RsaSha256),
        };
        var token = new JsonWebTokenHandler().CreateToken(descriptor);
        Assert.False(await IsValid(JwtTestKeys.CurrentOnly(), token));
    }

    // ---- issuer / audience / signature / expiry ----

    [Fact]
    public async Task WrongIssuer_Rejected()
        => Assert.False(await IsValid(JwtTestKeys.CurrentOnly(), Sign(CurrentBytes, "HS256", JwtTestKeys.CurrentKid, iss: "https://evil.example")));

    [Fact]
    public async Task WrongAudience_Rejected()
        => Assert.False(await IsValid(JwtTestKeys.CurrentOnly(), Sign(CurrentBytes, "HS256", JwtTestKeys.CurrentKid, aud: "someone-else")));

    [Fact]
    public async Task BadSignature_Rejected()
    {
        // Correct current kid, but signed with a different (wrong) 32-byte key.
        var wrongKey = Convert.FromBase64String(JwtTestKeys.Key32(0x33));
        Assert.False(await IsValid(JwtTestKeys.CurrentOnly(), Sign(wrongKey, "HS256", JwtTestKeys.CurrentKid)));
    }

    [Fact]
    public async Task ExpiredBeyondSkew_Rejected()
    {
        var now = new DateTime(2026, 9, 17, 12, 0, 0, DateTimeKind.Utc);
        // Expired 120 s ago — beyond the explicit 60 s skew.
        var token = Sign(CurrentBytes, "HS256", JwtTestKeys.CurrentKid, expUtc: now.AddSeconds(-120), iatUtc: now.AddSeconds(-1020));
        Assert.False(await IsValid(JwtTestKeys.CurrentOnly(), token));
    }

    [Fact]
    public async Task ExpiredWithinSkew_Accepted()
    {
        var now = DateTime.UtcNow;
        // Expired 30 s ago — inside the explicit 60 s skew → still accepted.
        var token = Sign(CurrentBytes, "HS256", JwtTestKeys.CurrentKid, expUtc: now.AddSeconds(-30), iatUtc: now.AddSeconds(-930));
        Assert.True(await IsValid(JwtTestKeys.CurrentOnly(), token));
    }

    // ---- fail-closed key configuration (ctor) ----

    [Fact]
    public void Ctor_CurrentKeyShorterThan32Bytes_Throws()
    {
        var o = JwtTestKeys.CurrentOnly();
        o.SigningKey = Convert.ToBase64String(new byte[16]);
        Assert.Throws<InvalidOperationException>(() => new JwtTokenValidationParametersFactory(o));
    }

    [Fact]
    public void Ctor_MalformedBase64CurrentKey_Throws()
    {
        var o = JwtTestKeys.CurrentOnly();
        o.SigningKey = "!!!not-base64!!!";
        Assert.Throws<InvalidOperationException>(() => new JwtTokenValidationParametersFactory(o));
    }

    [Fact]
    public void Ctor_BlankCurrentKid_Throws()
    {
        var o = JwtTestKeys.CurrentOnly();
        o.KeyId = "";
        Assert.Throws<InvalidOperationException>(() => new JwtTokenValidationParametersFactory(o));
    }

    [Fact]
    public void Ctor_PreviousKeyOnly_Throws()
    {
        var o = JwtTestKeys.CurrentOnly();
        o.PreviousSigningKey = JwtTestKeys.PreviousKey;
        Assert.Throws<InvalidOperationException>(() => new JwtTokenValidationParametersFactory(o));
    }

    [Fact]
    public void Ctor_PreviousKidOnly_Throws()
    {
        var o = JwtTestKeys.CurrentOnly();
        o.PreviousKeyId = JwtTestKeys.PreviousKid;
        Assert.Throws<InvalidOperationException>(() => new JwtTokenValidationParametersFactory(o));
    }

    [Fact]
    public void Ctor_MalformedPreviousKey_Throws()
    {
        var o = JwtTestKeys.WithPrevious();
        o.PreviousSigningKey = "@@bad@@";
        Assert.Throws<InvalidOperationException>(() => new JwtTokenValidationParametersFactory(o));
    }

    [Fact]
    public void Ctor_ShortPreviousKey_Throws()
    {
        var o = JwtTestKeys.WithPrevious();
        o.PreviousSigningKey = Convert.ToBase64String(new byte[16]);
        Assert.Throws<InvalidOperationException>(() => new JwtTokenValidationParametersFactory(o));
    }
}
