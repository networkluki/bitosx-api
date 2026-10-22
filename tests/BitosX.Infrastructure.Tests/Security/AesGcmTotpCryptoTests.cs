using System.Security.Cryptography;
using BitosX.Infrastructure.Security;

namespace BitosX.Infrastructure.Tests.Security;

public sealed class AesGcmTotpCryptoTests
{
    private static AesGcmTotpCrypto Crypto(byte[]? key = null)
        => new(new TotpCryptoOptions { Key = Convert.ToBase64String(key ?? RandomNumberGenerator.GetBytes(32)) });

    [Fact]
    public void RoundTrip_BoundToAccount()
    {
        var crypto = Crypto();
        var account = Guid.NewGuid();
        var secret = RandomNumberGenerator.GetBytes(20);

        var protectedSecret = crypto.Protect(secret, account);
        Assert.NotEqual(secret, protectedSecret.Ciphertext);
        Assert.True(crypto.TryUnprotect(protectedSecret, account, out var opened));
        Assert.Equal(secret, opened);

        Assert.False(crypto.TryUnprotect(protectedSecret, Guid.NewGuid(), out _), "another account's id must not open it (AAD)");
        var tampered = protectedSecret with { Ciphertext = (byte[])protectedSecret.Ciphertext.Clone() };
        tampered.Ciphertext[0] ^= 1;
        Assert.False(crypto.TryUnprotect(tampered, account, out _));
        Assert.False(Crypto().TryUnprotect(protectedSecret, account, out _), "another key must not open it");
    }

    [Fact]
    public void FreshNoncePerCall()
    {
        var crypto = Crypto();
        var account = Guid.NewGuid();
        var a = crypto.Protect(new byte[20], account);
        var b = crypto.Protect(new byte[20], account);
        Assert.NotEqual(a.Nonce, b.Nonce);
        Assert.NotEqual(a.Ciphertext, b.Ciphertext);
    }

    [Fact]
    public void RecoveryVerifier_IsKeyed_AndStable()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        var a = Crypto(key);
        var b = Crypto(key);
        Assert.Equal(a.RecoveryCodeVerifier("abcdefghjk"), b.RecoveryCodeVerifier("abcdefghjk"));
        Assert.NotEqual(a.RecoveryCodeVerifier("abcdefghjk"), a.RecoveryCodeVerifier("abcdefghjm"));
        Assert.NotEqual(a.RecoveryCodeVerifier("abcdefghjk"), Crypto().RecoveryCodeVerifier("abcdefghjk"));
        Assert.Equal(32, a.RecoveryCodeVerifier("abcdefghjk").Length);
    }

    [Theory]
    [InlineData("")]
    [InlineData("not base64!")]
    [InlineData("c2hvcnQ=")]
    public void MalformedKey_FailsClosed(string key)
        => Assert.Throws<InvalidOperationException>(() => new AesGcmTotpCrypto(new TotpCryptoOptions { Key = key }));
}
