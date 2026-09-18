using BitosX.Application.Security;
using BitosX.Infrastructure.Security;
using Microsoft.IdentityModel.JsonWebTokens;

namespace BitosX.Infrastructure.Tests.Security;

/// <summary>Issuance-only JWT service: claim/kid/alg/lifetime correctness + fail-closed key config.</summary>
public sealed class JwtAccessTokenServiceTests
{
    private static readonly DateTime Now = new(2026, 9, 17, 12, 0, 30, DateTimeKind.Utc);
    private static readonly Guid Account = Guid.Parse("11111111-1111-1111-1111-111111111111");
    private static readonly Guid Session = Guid.Parse("22222222-2222-2222-2222-222222222222");

    private static JsonWebToken Issue(JwtOptions options, out AccessToken issued)
    {
        var service = new JwtAccessTokenService(options);
        issued = service.Issue(Account, Session, Now);
        return new JsonWebTokenHandler().ReadJsonWebToken(issued.Token);
    }

    // ---- issuance ----

    [Fact]
    public void Issue_HeaderCarriesCurrentKid_AndHs256()
    {
        var jwt = Issue(JwtTestKeys.WithPrevious(), out _);
        Assert.Equal(JwtTestKeys.CurrentKid, jwt.Kid);
        Assert.Equal("HS256", jwt.Alg);
    }

    [Fact]
    public void Issue_PreviousKeyNeverUsedForSigning()
    {
        // With rotation configured, the token must still be signed under the CURRENT kid.
        var jwt = Issue(JwtTestKeys.WithPrevious(), out _);
        Assert.Equal(JwtTestKeys.CurrentKid, jwt.Kid);
        Assert.NotEqual(JwtTestKeys.PreviousKid, jwt.Kid);
    }

    [Fact]
    public void Issue_ExactIssuerAndAudience()
    {
        var jwt = Issue(JwtTestKeys.CurrentOnly(), out _);
        Assert.Equal("https://api.bitosx.se", jwt.Issuer);
        Assert.Contains("bitosx-api", jwt.Audiences);
    }

    [Fact]
    public void Issue_SubAndSidAreExactGuids()
    {
        var jwt = Issue(JwtTestKeys.CurrentOnly(), out _);
        Assert.Equal(Account.ToString(), jwt.GetPayloadValue<string>("sub"));
        Assert.Equal(Session.ToString(), jwt.GetPayloadValue<string>("sid"));
    }

    [Fact]
    public void Issue_JtiPresent_AndMatchesReturnedModel()
    {
        var jwt = Issue(JwtTestKeys.CurrentOnly(), out var issued);
        Assert.Equal(issued.Jti.ToString(), jwt.GetPayloadValue<string>("jti"));
        Assert.NotEqual(Guid.Empty, issued.Jti);
    }

    [Fact]
    public void Issue_JtiIsUniquePerCall()
    {
        var service = new JwtAccessTokenService(JwtTestKeys.CurrentOnly());
        var a = service.Issue(Account, Session, Now);
        var b = service.Issue(Account, Session, Now);
        Assert.NotEqual(a.Jti, b.Jti);
    }

    [Fact]
    public void Issue_IatIsNow_AndExpIsExactlyPlus900()
    {
        var jwt = Issue(JwtTestKeys.CurrentOnly(), out var issued);
        Assert.Equal(Now, jwt.IssuedAt);
        Assert.Equal(900, (jwt.ValidTo - jwt.IssuedAt).TotalSeconds);
        Assert.Equal(Now.AddSeconds(900), issued.ExpiresAt);
    }

    [Fact]
    public void Issue_ContainsNoForbiddenClaims()
    {
        var jwt = Issue(JwtTestKeys.CurrentOnly(), out _);
        Assert.False(jwt.TryGetPayloadValue<string>("email", out _));
        Assert.False(jwt.TryGetPayloadValue<string>("phone", out _));
        Assert.False(jwt.TryGetPayloadValue<string>("role", out _));
        foreach (var claim in jwt.Claims)
        {
            Assert.DoesNotContain("vault", claim.Type, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("password", claim.Type, StringComparison.OrdinalIgnoreCase);
        }
    }

    [Fact]
    public void Issue_ClaimSetIsMinimal()
    {
        var jwt = Issue(JwtTestKeys.CurrentOnly(), out _);
        var types = jwt.Claims.Select(c => c.Type).ToHashSet();
        // Only the approved minimal claims (nbf is an allowed default time claim).
        var allowed = new HashSet<string> { "sub", "sid", "jti", "iat", "exp", "iss", "aud", "nbf" };
        Assert.True(types.IsSubsetOf(allowed), $"unexpected claims: {string.Join(",", types.Except(allowed))}");
    }

    // ---- fail-closed key configuration (ctor) ----

    [Fact]
    public void Ctor_CurrentKeyShorterThan32Bytes_Throws()
    {
        var o = JwtTestKeys.CurrentOnly();
        o.SigningKey = Convert.ToBase64String(new byte[16]);
        Assert.Throws<InvalidOperationException>(() => new JwtAccessTokenService(o));
    }

    [Fact]
    public void Ctor_MalformedBase64CurrentKey_Throws()
    {
        var o = JwtTestKeys.CurrentOnly();
        o.SigningKey = "!!!not-base64!!!";
        Assert.Throws<InvalidOperationException>(() => new JwtAccessTokenService(o));
    }

    [Fact]
    public void Ctor_BlankCurrentKid_Throws()
    {
        var o = JwtTestKeys.CurrentOnly();
        o.KeyId = "   ";
        Assert.Throws<InvalidOperationException>(() => new JwtAccessTokenService(o));
    }

    [Fact]
    public void Ctor_PreviousKeyWithoutPreviousKid_Throws()
    {
        var o = JwtTestKeys.CurrentOnly();
        o.PreviousSigningKey = JwtTestKeys.PreviousKey; // no PreviousKeyId
        Assert.Throws<InvalidOperationException>(() => new JwtAccessTokenService(o));
    }

    [Fact]
    public void Ctor_PreviousKidWithoutPreviousKey_Throws()
    {
        var o = JwtTestKeys.CurrentOnly();
        o.PreviousKeyId = JwtTestKeys.PreviousKid; // no PreviousSigningKey
        Assert.Throws<InvalidOperationException>(() => new JwtAccessTokenService(o));
    }

    [Fact]
    public void Ctor_ShortPreviousKey_Throws()
    {
        var o = JwtTestKeys.WithPrevious();
        o.PreviousSigningKey = Convert.ToBase64String(new byte[16]);
        Assert.Throws<InvalidOperationException>(() => new JwtAccessTokenService(o));
    }

    [Fact]
    public void Ctor_MalformedPreviousKey_Throws()
    {
        var o = JwtTestKeys.WithPrevious();
        o.PreviousSigningKey = "@@not-base64@@";
        Assert.Throws<InvalidOperationException>(() => new JwtAccessTokenService(o));
    }
}
