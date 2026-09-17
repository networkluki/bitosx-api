using BitosX.Application.Security;

namespace BitosX.Application.Tests;

/// <summary>
/// Guards that secret-bearing auth primitives never expose their secret members through
/// the (record) ToString(): a stray log/interpolation of one of these objects must not leak
/// the JWT or the plaintext refresh token. No object is logged here.
/// </summary>
public sealed class AuthPrimitivesRedactionTests
{
    private const string SecretJwt = "HEADER.PAYLOAD.SIGNATURE-do-not-leak-abc123";
    private const string SecretRefresh = "plaintext-refresh-token-do-not-leak-xyz789";
    private const string RedactionMarker = "<redacted>";

    [Fact]
    public void AccessToken_ToString_DoesNotContainToken()
    {
        var s = new AccessToken(SecretJwt, new DateTime(2026, 9, 17, 12, 15, 0, DateTimeKind.Utc), Guid.NewGuid()).ToString();
        Assert.DoesNotContain(SecretJwt, s, StringComparison.Ordinal);
        Assert.Contains(RedactionMarker, s, StringComparison.Ordinal);
    }

    [Fact]
    public void AccessToken_ToString_MayExposeOnlyNonSecretMetadata()
    {
        var jti = Guid.NewGuid();
        var expires = new DateTime(2026, 9, 17, 12, 15, 0, DateTimeKind.Utc);
        var s = new AccessToken(SecretJwt, expires, jti).ToString();
        // Non-secret metadata is allowed and useful for diagnostics.
        Assert.Contains(jti.ToString(), s, StringComparison.Ordinal);
    }

    [Fact]
    public void GeneratedRefreshToken_ToString_DoesNotContainPlaintextToken()
    {
        var s = new GeneratedRefreshToken(SecretRefresh, new byte[32]).ToString();
        Assert.DoesNotContain(SecretRefresh, s, StringComparison.Ordinal);
        Assert.Contains(RedactionMarker, s, StringComparison.Ordinal);
    }

    [Fact]
    public void GeneratedRefreshToken_ToString_DoesNotExposeVerifierMaterial()
    {
        // A recognizable verifier byte pattern must not appear in any textual form.
        var verifier = Enumerable.Range(0, 32).Select(i => (byte)0xAB).ToArray();
        var s = new GeneratedRefreshToken(SecretRefresh, verifier).ToString();

        Assert.DoesNotContain("AB", s, StringComparison.OrdinalIgnoreCase);           // hex
        Assert.DoesNotContain(Convert.ToBase64String(verifier), s, StringComparison.Ordinal); // base64
        Assert.DoesNotContain("171, 171", s, StringComparison.Ordinal);              // decimal join
    }
}
