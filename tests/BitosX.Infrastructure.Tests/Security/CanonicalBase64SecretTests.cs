using BitosX.Application.Security;
using BitosX.Infrastructure.Security;

namespace BitosX.Infrastructure.Tests.Security;

/// <summary>
/// M-1: JWT signing-key Base64 config (JwtSigningKey / JwtPreviousSigningKey) must be canonical
/// standard Base64 with no whitespace and ≥ 32 decoded bytes; anything else fails closed. Exercised
/// through the real ctors that consume each key (shared internal parser). The refresh token no
/// longer uses a Base64 secret (SHA-256 verifier), so it is not covered here.
/// </summary>
public sealed class CanonicalBase64SecretTests
{
    private static string Insert(string s, int at, string what) => s[..at] + what + s[at..];

    private static void AssertJwtCurrentKeyRejected(string key)
    {
        var o = JwtTestKeys.CurrentOnly();
        o.SigningKey = key;
        Assert.Throws<InvalidOperationException>(() => new JwtAccessTokenService(o));
        // The validation-parameters factory shares the same parser.
        var o2 = JwtTestKeys.CurrentOnly();
        o2.SigningKey = key;
        Assert.Throws<InvalidOperationException>(() => new JwtTokenValidationParametersFactory(o2));
    }

    private static void AssertJwtPreviousKeyRejected(string key)
    {
        var o = JwtTestKeys.WithPrevious();
        o.PreviousSigningKey = key;
        Assert.Throws<InvalidOperationException>(() => new JwtAccessTokenService(o));
    }

    // ---- JWT current key ----

    [Fact] public void JwtCurrentKey_LeadingWhitespace_Rejected() => AssertJwtCurrentKeyRejected(" " + JwtTestKeys.CurrentKey);
    [Fact] public void JwtCurrentKey_TrailingWhitespace_Rejected() => AssertJwtCurrentKeyRejected(JwtTestKeys.CurrentKey + " ");
    [Fact] public void JwtCurrentKey_EmbeddedSpace_Rejected() => AssertJwtCurrentKeyRejected(Insert(JwtTestKeys.CurrentKey, 10, " "));
    [Fact] public void JwtCurrentKey_EmbeddedNewline_Rejected() => AssertJwtCurrentKeyRejected(Insert(JwtTestKeys.CurrentKey, 10, "\n"));
    [Fact] public void JwtCurrentKey_EmbeddedTab_Rejected() => AssertJwtCurrentKeyRejected(Insert(JwtTestKeys.CurrentKey, 10, "\t"));

    [Fact]
    public void JwtCurrentKey_NonCanonical_Rejected()
    {
        Assert.True(Base64TestHelper.TryMakeNonCanonical(JwtTestKeys.CurrentKey, out var nonCanonical),
            "expected a constructible non-canonical form for a 32-byte key");
        AssertJwtCurrentKeyRejected(nonCanonical);
    }

    [Fact]
    public void JwtCurrentKey_Canonical_Accepted()
    {
        // Canonical key must NOT throw (regression guard for the strict parser).
        _ = new JwtAccessTokenService(JwtTestKeys.CurrentOnly());
        _ = new JwtTokenValidationParametersFactory(JwtTestKeys.CurrentOnly());
    }

    // ---- JWT previous key ----

    [Fact] public void JwtPreviousKey_TrailingWhitespace_Rejected() => AssertJwtPreviousKeyRejected(JwtTestKeys.PreviousKey + " ");
    [Fact] public void JwtPreviousKey_EmbeddedNewline_Rejected() => AssertJwtPreviousKeyRejected(Insert(JwtTestKeys.PreviousKey, 8, "\n"));

    [Fact]
    public void JwtPreviousKey_NonCanonical_Rejected()
    {
        Assert.True(Base64TestHelper.TryMakeNonCanonical(JwtTestKeys.PreviousKey, out var nonCanonical));
        AssertJwtPreviousKeyRejected(nonCanonical);
    }

    // Note: the refresh-token factory no longer uses a Base64 pepper secret (verifier is
    // SHA-256 of the raw token bytes), so CanonicalBase64Secret now guards only the JWT keys.
}
