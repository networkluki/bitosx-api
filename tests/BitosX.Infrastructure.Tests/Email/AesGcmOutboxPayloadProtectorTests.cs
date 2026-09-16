using System.Security.Cryptography;
using System.Text;
using BitosX.Application.Email;
using BitosX.Infrastructure.Email;

namespace BitosX.Infrastructure.Tests.Email;

public sealed class AesGcmOutboxPayloadProtectorTests
{
    private static string Key() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));

    private static AesGcmOutboxPayloadProtector Protector(string? key = null)
        => new(new EmailOutboxCryptoOptions { Key = key ?? Key() });

    private static OutboxPayload SamplePayload(string token = "tok_ABC123")
        => new(1, Guid.NewGuid(), token, DateTime.UtcNow.AddMinutes(30), "user@example.com");

    private static OutboxAad Aad(Guid? id = null, string type = "email_verification", string recipient = "user@example.com")
        => new(id ?? Guid.NewGuid(), 1, type, recipient);

    [Fact]
    public void Protect_Then_Unprotect_RoundTrips()
    {
        var p = Protector();
        var aad = Aad();
        var payload = SamplePayload();

        var protectedPayload = p.Protect(payload, aad);
        Assert.True(p.TryUnprotect(protectedPayload, aad, out var round));
        Assert.Equal(payload, round);
    }

    [Fact]
    public void Protect_UsesDistinctNonces()
    {
        var p = Protector();
        var aad = Aad();
        var a = p.Protect(SamplePayload(), aad);
        var b = p.Protect(SamplePayload(), aad);
        Assert.NotEqual(Convert.ToBase64String(a.Nonce), Convert.ToBase64String(b.Nonce));
    }

    [Fact]
    public void Ciphertext_DoesNotContainTokenBytes()
    {
        var p = Protector();
        var token = "SUPER-SECRET-TOKEN-abcdefghijklmnop";
        var protectedPayload = p.Protect(SamplePayload(token), Aad());
        var tokenBytes = Encoding.UTF8.GetBytes(token);
        Assert.False(ContainsSubsequence(protectedPayload.Ciphertext, tokenBytes));
    }

    [Fact]
    public void WrongKey_FailsAuthentication()
    {
        var aad = Aad();
        var protectedPayload = Protector().Protect(SamplePayload(), aad);
        Assert.False(Protector().TryUnprotect(protectedPayload, aad, out var payload));
        Assert.Null(payload);
    }

    [Fact]
    public void TamperedCiphertextTagNonce_Fail()
    {
        var p = Protector();
        var aad = Aad();
        var pp = p.Protect(SamplePayload(), aad);

        var ct = (byte[])pp.Ciphertext.Clone(); ct[0] ^= 0xFF;
        Assert.False(p.TryUnprotect(pp with { Ciphertext = ct }, aad, out _));

        var tag = (byte[])pp.Tag.Clone(); tag[0] ^= 0xFF;
        Assert.False(p.TryUnprotect(pp with { Tag = tag }, aad, out _));

        var nonce = (byte[])pp.Nonce.Clone(); nonce[0] ^= 0xFF;
        Assert.False(p.TryUnprotect(pp with { Nonce = nonce }, aad, out _));
    }

    [Fact]
    public void AadTamper_AnyField_FailsAuthentication()
    {
        var p = Protector();
        var aad = Aad(recipient: "user@example.com");
        var pp = p.Protect(SamplePayload(), aad);

        Assert.False(p.TryUnprotect(pp, aad with { RecipientEmail = "attacker@evil.example" }, out _));
        Assert.False(p.TryUnprotect(pp, aad with { MessageType = "something_else" }, out _));
        Assert.False(p.TryUnprotect(pp, aad with { Id = Guid.NewGuid() }, out _));
        Assert.False(p.TryUnprotect(pp, aad with { Version = 2 }, out _));
        // Correct AAD still works.
        Assert.True(p.TryUnprotect(pp, aad, out _));
    }

    [Fact]
    public void CanonicalAad_LengthPrefixed_NoConcatenationCollision()
    {
        // ("ab","c") vs ("a","bc") would collide under naive concatenation.
        var p = Protector();
        var id = Guid.NewGuid();
        var aad1 = new OutboxAad(id, 1, "ab", "c");
        var aad2 = new OutboxAad(id, 1, "a", "bc");
        var pp = p.Protect(SamplePayload(), aad1);
        Assert.True(p.TryUnprotect(pp, aad1, out _));
        Assert.False(p.TryUnprotect(pp, aad2, out _)); // distinct canonical AAD → auth fails
    }

    private static bool ContainsSubsequence(byte[] haystack, byte[] needle)
    {
        for (var i = 0; i + needle.Length <= haystack.Length; i++)
        {
            var match = true;
            for (var j = 0; j < needle.Length; j++)
            {
                if (haystack[i + j] != needle[j]) { match = false; break; }
            }
            if (match) return true;
        }
        return false;
    }
}
