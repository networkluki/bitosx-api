using System.Security.Cryptography;
using BitosX.Infrastructure.Security;

namespace BitosX.Infrastructure.Tests.Security;

/// <summary>
/// Refresh-token generation + strict Base64URL parser with a <c>SHA-256(raw token bytes)</c>
/// verifier. No server secret is involved (the token is 256 CSPRNG bits).
/// </summary>
public sealed class Sha256RefreshTokenFactoryTests
{
    private static Sha256RefreshTokenFactory Factory() => new();

    private static byte[] DecodeB64Url(string v)
    {
        var s = v.Replace('-', '+').Replace('_', '/');
        s += (s.Length % 4) switch { 2 => "==", 3 => "=", _ => "" };
        return Convert.FromBase64String(s);
    }

    // ---- construction (no secret required) ----

    [Fact]
    public void Factory_RequiresNoServerSecret()
    {
        // Parameterless construction is the proof: no pepper/secret is needed.
        var f = new Sha256RefreshTokenFactory();
        var g = f.Generate();
        Assert.Equal(43, g.TokenBase64Url.Length);
    }

    // ---- generation ----

    [Fact]
    public void Generate_TokenIs43CharsUnpadded_Decodes32Bytes()
    {
        var g = Factory().Generate();
        Assert.Equal(43, g.TokenBase64Url.Length);
        Assert.DoesNotContain('=', g.TokenBase64Url);
        Assert.Equal(32, DecodeB64Url(g.TokenBase64Url).Length);
    }

    [Fact]
    public void Generate_TokenUsesOnlyBase64UrlAlphabet()
    {
        var g = Factory().Generate();
        Assert.DoesNotContain('+', g.TokenBase64Url);
        Assert.DoesNotContain('/', g.TokenBase64Url);
        Assert.All(g.TokenBase64Url, c => Assert.True(char.IsAsciiLetterOrDigit(c) || c is '-' or '_'));
    }

    [Fact]
    public void Generate_ProducesDistinctTokens_Csprng()
    {
        var f = Factory();
        Assert.NotEqual(f.Generate().TokenBase64Url, f.Generate().TokenBase64Url);
    }

    [Fact]
    public void Generate_VerifierIs32Bytes_AndIsSha256OfRawTokenBytes()
    {
        var g = Factory().Generate();
        Assert.Equal(32, g.Verifier.Length);
        var expected = SHA256.HashData(DecodeB64Url(g.TokenBase64Url));
        Assert.True(CryptographicOperations.FixedTimeEquals(expected, g.Verifier));
    }

    // ---- parsing / verifier ----

    [Fact]
    public void TryComputeVerifier_ValidGeneratedToken_EqualsSha256OfRawBytes()
    {
        var f = Factory();
        var g = f.Generate();
        Assert.True(f.TryComputeVerifier(g.TokenBase64Url, out var v));
        Assert.True(CryptographicOperations.FixedTimeEquals(v, g.Verifier));
        Assert.True(CryptographicOperations.FixedTimeEquals(v, SHA256.HashData(DecodeB64Url(g.TokenBase64Url))));
    }

    [Fact]
    public void TryComputeVerifier_SameTokenBytes_AlwaysSameVerifier()
    {
        var g = Factory().Generate();
        Factory().TryComputeVerifier(g.TokenBase64Url, out var v1);
        Factory().TryComputeVerifier(g.TokenBase64Url, out var v2);
        Assert.True(CryptographicOperations.FixedTimeEquals(v1, v2)); // deterministic, no secret
    }

    [Fact]
    public void TryComputeVerifier_DifferentTokens_DifferentVerifiers()
    {
        var f = Factory();
        var a = f.Generate();
        var b = f.Generate();
        f.TryComputeVerifier(a.TokenBase64Url, out var va);
        f.TryComputeVerifier(b.TokenBase64Url, out var vb);
        Assert.False(CryptographicOperations.FixedTimeEquals(va, vb));
    }

    [Theory]
    [InlineData("")]
    [InlineData("AAAA")]
    public void TryComputeVerifier_WrongLength_Short_Rejected(string token)
        => Assert.False(Factory().TryComputeVerifier(token, out _));

    [Fact] public void TryComputeVerifier_42Chars_Rejected() => Assert.False(Factory().TryComputeVerifier(new string('A', 42), out _));
    [Fact] public void TryComputeVerifier_44Chars_Rejected() => Assert.False(Factory().TryComputeVerifier(new string('A', 44), out _));

    [Fact]
    public void TryComputeVerifier_PaddingRejected()
    {
        var padded = Convert.ToBase64String(new byte[32]).Replace('+', '-').Replace('/', '_'); // 44 chars, ends '='
        Assert.Contains('=', padded);
        Assert.False(Factory().TryComputeVerifier(padded, out _));
    }

    [Fact] public void TryComputeVerifier_PlusRejected() => Assert.False(Factory().TryComputeVerifier(new string('A', 42) + "+", out _));
    [Fact] public void TryComputeVerifier_SlashRejected() => Assert.False(Factory().TryComputeVerifier(new string('A', 42) + "/", out _));

    [Fact]
    public void TryComputeVerifier_WhitespaceRejected()
    {
        var g = Factory().Generate();
        Assert.False(Factory().TryComputeVerifier(" " + g.TokenBase64Url[1..], out _));
    }

    [Fact] public void TryComputeVerifier_IllegalCharacterRejected() => Assert.False(Factory().TryComputeVerifier(new string('A', 42) + "!", out _));

    [Fact]
    public void TryComputeVerifier_NonCanonicalBase64Url_Rejected()
    {
        // 'A'x42 + 'B': valid alphabet, decodes to 32 bytes, but non-canonical (canonical final char is 'A').
        var nonCanonical = new string('A', 42) + "B";
        Assert.Equal(43, nonCanonical.Length);
        Assert.False(Factory().TryComputeVerifier(nonCanonical, out _));
    }

    [Fact]
    public void TryComputeVerifier_MalformedInput_DoesNotThrow_ReturnsFalse()
    {
        var f = Factory();
        foreach (var bad in new[] { "", "   ", "!!!", new string('A', 100), "====" })
        {
            var threw = false;
            bool result;
            try { result = f.TryComputeVerifier(bad, out _); }
            catch { threw = true; result = true; }
            Assert.False(threw, $"threw on '{bad}'");
            Assert.False(result, $"accepted '{bad}'");
        }
    }

    // ---- security ----

    [Fact]
    public void Verifier_DoesNotEqualRawTokenBytes()
    {
        var g = Factory().Generate();
        var raw = DecodeB64Url(g.TokenBase64Url);
        Assert.False(CryptographicOperations.FixedTimeEquals(raw, g.Verifier));
    }
}
