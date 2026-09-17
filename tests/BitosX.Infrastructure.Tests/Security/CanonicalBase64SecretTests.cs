using BitosX.Application.Security;
using BitosX.Infrastructure.Security;

namespace BitosX.Infrastructure.Tests.Security;

/// <summary>
/// M-1: secret Base64 config (JwtSigningKey / JwtPreviousSigningKey / RefreshTokenPepper) must be
/// canonical standard Base64 with no whitespace and ≥ 32 decoded bytes; anything else fails closed.
/// Exercised through the real ctors that consume each secret (shared internal parser).
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

    private static void AssertPepperRejected(string pepper)
        => Assert.Throws<InvalidOperationException>(() => new HmacRefreshTokenFactory(new RefreshTokenOptions { Pepper = pepper }));

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

    // ---- refresh pepper ----

    private static string ValidPepper => Convert.ToBase64String(Enumerable.Repeat((byte)0x5A, 32).ToArray());

    [Fact] public void Pepper_LeadingWhitespace_Rejected() => AssertPepperRejected(" " + ValidPepper);
    [Fact] public void Pepper_TrailingWhitespace_Rejected() => AssertPepperRejected(ValidPepper + " ");
    [Fact] public void Pepper_EmbeddedSpace_Rejected() => AssertPepperRejected(Insert(ValidPepper, 10, " "));
    [Fact] public void Pepper_EmbeddedNewline_Rejected() => AssertPepperRejected(Insert(ValidPepper, 10, "\n"));
    [Fact] public void Pepper_EmbeddedTab_Rejected() => AssertPepperRejected(Insert(ValidPepper, 10, "\t"));

    [Fact]
    public void Pepper_NonCanonical_Rejected()
    {
        Assert.True(Base64TestHelper.TryMakeNonCanonical(ValidPepper, out var nonCanonical));
        AssertPepperRejected(nonCanonical);
    }

    [Fact]
    public void Pepper_Canonical_Accepted()
        => _ = new HmacRefreshTokenFactory(new RefreshTokenOptions { Pepper = ValidPepper });
}
