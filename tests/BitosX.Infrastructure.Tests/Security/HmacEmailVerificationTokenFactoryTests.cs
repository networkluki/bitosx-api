using System.Security.Cryptography;
using BitosX.Application.Verification;
using BitosX.Infrastructure.Security;

namespace BitosX.Infrastructure.Tests.Security;

public sealed class HmacEmailVerificationTokenFactoryTests
{
    private static HmacEmailVerificationTokenFactory Factory(string pepper = "test-pepper-please-use-a-long-random-value-in-prod")
        => new(new EmailVerificationSecurityOptions { Pepper = pepper });

    private static byte[] Base64UrlDecode(string v)
    {
        var s = v.Replace('-', '+').Replace('_', '/');
        s += (s.Length % 4) switch { 2 => "==", 3 => "=", _ => "" };
        return Convert.FromBase64String(s);
    }

    [Fact]
    public void GenerateToken_Produces256BitToken_And32ByteVerifier()
    {
        var t = Factory().GenerateToken();
        Assert.Equal(32, Base64UrlDecode(t.TokenBase64Url).Length);
        Assert.Equal(32, t.VerifierHash.Length);
        Assert.DoesNotContain('=', t.TokenBase64Url); // unpadded url-safe
    }

    [Fact]
    public void GenerateToken_TokensDiffer()
    {
        var f = Factory();
        Assert.NotEqual(f.GenerateToken().TokenBase64Url, f.GenerateToken().TokenBase64Url);
    }

    [Fact]
    public void ComputeVerifier_IsDeterministic_AndMatchesGenerated()
    {
        var f = Factory();
        var t = f.GenerateToken();
        var recomputed = f.ComputeVerifier(t.TokenBase64Url);
        Assert.True(CryptographicOperations.FixedTimeEquals(recomputed, t.VerifierHash));
    }

    [Fact]
    public void DifferentPepper_ProducesDifferentVerifier()
    {
        var f1 = Factory("pepper-one-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        var t = f1.GenerateToken();
        var f2 = Factory("pepper-two-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
        Assert.False(CryptographicOperations.FixedTimeEquals(f2.ComputeVerifier(t.TokenBase64Url), t.VerifierHash));
    }

    [Fact]
    public void MissingPepper_Throws()
        => Assert.Throws<InvalidOperationException>(() => new HmacEmailVerificationTokenFactory(new EmailVerificationSecurityOptions { Pepper = "" }));
}
