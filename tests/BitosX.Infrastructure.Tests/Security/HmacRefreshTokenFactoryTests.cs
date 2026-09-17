using System.Security.Cryptography;
using BitosX.Application.Security;
using BitosX.Infrastructure.Security;

namespace BitosX.Infrastructure.Tests.Security;

/// <summary>
/// Refresh-token generation, HMAC verifier, and strict Base64URL parser. Pepper values here
/// are obviously test-only (Base64 of a fixed 32-byte pattern); real peppers are CSPRNG and
/// live only in the secret store.
/// </summary>
public sealed class HmacRefreshTokenFactoryTests
{
    private static string Pepper(byte seed) => Convert.ToBase64String(Enumerable.Repeat(seed, 32).ToArray());

    private static HmacRefreshTokenFactory Factory(byte pepperSeed = 0x40)
        => new(new RefreshTokenOptions { Pepper = Pepper(pepperSeed) });

    private static byte[] DecodeB64Url(string v)
    {
        var s = v.Replace('-', '+').Replace('_', '/');
        s += (s.Length % 4) switch { 2 => "==", 3 => "=", _ => "" };
        return Convert.FromBase64String(s);
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
    public void Generate_ProducesDistinctTokens()
    {
        var f = Factory();
        Assert.NotEqual(f.Generate().TokenBase64Url, f.Generate().TokenBase64Url);
    }

    [Fact]
    public void Generate_VerifierIs32Bytes_AndMatchesHmacOverRawBytes()
    {
        var pepperSeed = (byte)0x55;
        var g = Factory(pepperSeed).Generate();
        Assert.Equal(32, g.Verifier.Length);

        var expected = HMACSHA256.HashData(Convert.FromBase64String(Pepper(pepperSeed)), DecodeB64Url(g.TokenBase64Url));
        Assert.True(CryptographicOperations.FixedTimeEquals(expected, g.Verifier));
    }

    [Fact]
    public void DifferentPepper_ProducesDifferentVerifier_ForSameToken()
    {
        var f1 = Factory(0x11);
        var g = f1.Generate();
        var f2 = Factory(0x22);
        Assert.True(f2.TryComputeVerifier(g.TokenBase64Url, out var v2));
        Assert.False(CryptographicOperations.FixedTimeEquals(v2, g.Verifier));
    }

    // ---- parsing ----

    [Fact]
    public void TryComputeVerifier_ValidGeneratedToken_RecomputesSameVerifier()
    {
        var f = Factory();
        var g = f.Generate();
        Assert.True(f.TryComputeVerifier(g.TokenBase64Url, out var v));
        Assert.True(CryptographicOperations.FixedTimeEquals(v, g.Verifier));
    }

    [Theory]
    [InlineData("")]                                              // empty
    [InlineData("AAAA")]                                          // too short (4)
    public void TryComputeVerifier_WrongLength_Short_Rejected(string token)
        => Assert.False(Factory().TryComputeVerifier(token, out _));

    [Fact]
    public void TryComputeVerifier_42Chars_Rejected()
        => Assert.False(Factory().TryComputeVerifier(new string('A', 42), out _));

    [Fact]
    public void TryComputeVerifier_44Chars_Rejected()
        => Assert.False(Factory().TryComputeVerifier(new string('A', 44), out _));

    [Fact]
    public void TryComputeVerifier_PaddingRejected()
    {
        // 32 zero bytes standard-base64 = 43 chars + '=' padding = 44; strip to a padded-looking 43+'='.
        var padded = Convert.ToBase64String(new byte[32]).Replace('+', '-').Replace('/', '_'); // ends with '='
        Assert.Contains('=', padded);
        Assert.False(Factory().TryComputeVerifier(padded, out _));
    }

    [Fact]
    public void TryComputeVerifier_PlusRejected()
    {
        var t = new string('A', 42) + "+";
        Assert.False(Factory().TryComputeVerifier(t, out _));
    }

    [Fact]
    public void TryComputeVerifier_SlashRejected()
    {
        var t = new string('A', 42) + "/";
        Assert.False(Factory().TryComputeVerifier(t, out _));
    }

    [Fact]
    public void TryComputeVerifier_WhitespaceRejected()
    {
        var g = Factory().Generate();
        Assert.False(Factory().TryComputeVerifier(" " + g.TokenBase64Url[1..], out _));
    }

    [Fact]
    public void TryComputeVerifier_IllegalCharacterRejected()
    {
        var t = new string('A', 42) + "!";
        Assert.False(Factory().TryComputeVerifier(t, out _));
    }

    [Fact]
    public void TryComputeVerifier_NonCanonicalBase64Url_Rejected()
    {
        // 43 chars, valid alphabet, decodes to 32 bytes — but the final char 'B' carries
        // non-zero padding bits, so it is NOT the canonical encoding of those bytes
        // (canonical would re-encode the final char to 'A'). Must be rejected.
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

    // ---- construction fail-closed ----

    [Fact]
    public void Ctor_BlankPepper_Throws()
        => Assert.Throws<InvalidOperationException>(() => new HmacRefreshTokenFactory(new RefreshTokenOptions { Pepper = "" }));

    [Fact]
    public void Ctor_ShortPepper_Throws()
        => Assert.Throws<InvalidOperationException>(() => new HmacRefreshTokenFactory(new RefreshTokenOptions { Pepper = Convert.ToBase64String(new byte[16]) }));

    [Fact]
    public void Ctor_MalformedBase64Pepper_Throws()
        => Assert.Throws<InvalidOperationException>(() => new HmacRefreshTokenFactory(new RefreshTokenOptions { Pepper = "!!!not-base64!!!" }));

    // ---- security ----

    [Fact]
    public void Verifier_DoesNotContainRawTokenBytes()
    {
        var g = Factory().Generate();
        var raw = DecodeB64Url(g.TokenBase64Url);
        // The 32-byte verifier must not simply equal the raw token bytes.
        Assert.False(CryptographicOperations.FixedTimeEquals(raw, g.Verifier));
    }
}
