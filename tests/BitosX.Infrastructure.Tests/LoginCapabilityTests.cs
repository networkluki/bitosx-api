using BitosX.Infrastructure.Accounts;
using Microsoft.Extensions.Configuration;

namespace BitosX.Infrastructure.Tests;

/// <summary>
/// LoginEnabled detection + fail-closed JWT/refresh config validation (Phase 2A.3b2).
/// Login is gated ONLY on the current JWT signing key (no refresh secret). All keys are
/// obviously test-only. Uses in-memory configuration (no DB).
/// </summary>
public sealed class LoginCapabilityTests
{
    private const string Conn = "Server=127.0.0.1;Port=3306;Database=bitosx;User ID=x;Password=y;GuidFormat=Char36";

    private static string Key32(byte seed) => Convert.ToBase64String(Enumerable.Repeat(seed, 32).ToArray());

    private static Dictionary<string, string?> BaseLogin() => new()
    {
        ["ConnectionStrings:Bitosx"] = Conn,
        ["Security:JwtSigningKey"] = Key32(0x11),
        ["Security:Jwt:KeyId"] = "k1",
    };

    private static Microsoft.Extensions.Configuration.IConfiguration Cfg(Dictionary<string, string?> d)
        => new ConfigurationBuilder().AddInMemoryCollection(d).Build();

    private static bool LoginEnabled(Dictionary<string, string?> d)
        => AccountsServiceCollectionExtensions.DetectCapabilities(Cfg(d)).LoginEnabled;

    private static void AssertThrows(Dictionary<string, string?> d)
        => Assert.Throws<InvalidOperationException>(() => AccountsServiceCollectionExtensions.DetectCapabilities(Cfg(d)));

    // ---- account core gating ----

    [Fact] public void NoConnection_LoginDisabled() { var d = BaseLogin(); d.Remove("ConnectionStrings:Bitosx"); Assert.False(LoginEnabled(d)); }

    [Fact]
    public void ConnectionButNoSigningKey_LoginDisabled_CoreEnabled()
    {
        var d = BaseLogin(); d.Remove("Security:JwtSigningKey"); d.Remove("Security:Jwt:KeyId");
        var caps = AccountsServiceCollectionExtensions.DetectCapabilities(Cfg(d));
        Assert.False(caps.LoginEnabled);
        Assert.True(caps.AccountCoreEnabled);
    }

    // ---- non-secret metadata alone must NOT enable login ----

    [Fact] public void KeyIdOnly_NoSigningKey_LoginDisabled() { var d = new Dictionary<string, string?> { ["ConnectionStrings:Bitosx"] = Conn, ["Security:Jwt:KeyId"] = "k1" }; Assert.False(LoginEnabled(d)); }

    [Fact]
    public void IssuerAudienceLifetimeMetadataOnly_NoSigningKey_LoginDisabled()
    {
        var d = new Dictionary<string, string?>
        {
            ["ConnectionStrings:Bitosx"] = Conn,
            ["Security:Jwt:Issuer"] = "https://api.bitosx.se",
            ["Security:Jwt:Audience"] = "bitosx-api",
            ["Security:Jwt:AccessTokenLifetimeSeconds"] = "900",
            ["Security:RefreshToken:IdleLifetimeSeconds"] = "2592000",
        };
        Assert.False(LoginEnabled(d));
    }

    // ---- valid current ----

    [Fact] public void ValidCurrent_LoginEnabled() => Assert.True(LoginEnabled(BaseLogin()));

    [Fact]
    public void ValidCurrent_NoSmtp_NoVerification_StillLoginEnabled()
    {
        var caps = AccountsServiceCollectionExtensions.DetectCapabilities(Cfg(BaseLogin()));
        Assert.True(caps.LoginEnabled);
        Assert.False(caps.EmailVerificationEnabled);
        Assert.False(caps.EmailDeliveryEnabled);
    }

    [Fact]
    public void ValidCurrent_WithVerificationEnabled_DeliveryDisabled_StillLoginEnabled()
    {
        var d = BaseLogin();
        d["Security:EmailVerificationPepper"] = "test-pepper-please-long-random";
        d["Security:EmailOutboxKey"] = Key32(0x33);
        var caps = AccountsServiceCollectionExtensions.DetectCapabilities(Cfg(d));
        Assert.True(caps.LoginEnabled);
        Assert.True(caps.EmailVerificationEnabled);
        Assert.False(caps.EmailDeliveryEnabled);
    }

    [Fact]
    public void ValidCurrent_NoRefreshSecretRequired_LoginEnabled()
    {
        var d = BaseLogin();
        Assert.DoesNotContain("Security:RefreshTokenPepper", d.Keys); // there is no refresh secret
        Assert.True(LoginEnabled(d));
    }

    // ---- malformed current JWT config ----

    [Fact] public void InvalidBase64Key_Throws() { var d = BaseLogin(); d["Security:JwtSigningKey"] = "!!!not-base64!!!"; AssertThrows(d); }
    [Fact] public void ShortKey_Throws() { var d = BaseLogin(); d["Security:JwtSigningKey"] = Convert.ToBase64String(new byte[16]); AssertThrows(d); }
    [Fact] public void MissingKid_Throws() { var d = BaseLogin(); d.Remove("Security:Jwt:KeyId"); AssertThrows(d); }
    [Fact] public void BlankKid_Throws() { var d = BaseLogin(); d["Security:Jwt:KeyId"] = "   "; AssertThrows(d); }
    [Fact] public void BlankIssuer_Throws() { var d = BaseLogin(); d["Security:Jwt:Issuer"] = ""; AssertThrows(d); }
    [Fact] public void BlankAudience_Throws() { var d = BaseLogin(); d["Security:Jwt:Audience"] = ""; AssertThrows(d); }
    [Fact] public void ZeroLifetime_Throws() { var d = BaseLogin(); d["Security:Jwt:AccessTokenLifetimeSeconds"] = "0"; AssertThrows(d); }
    [Fact] public void NegativeLifetime_Throws() { var d = BaseLogin(); d["Security:Jwt:AccessTokenLifetimeSeconds"] = "-5"; AssertThrows(d); }
    [Fact] public void NegativeSkew_Throws() { var d = BaseLogin(); d["Security:Jwt:ClockSkewSeconds"] = "-1"; AssertThrows(d); }

    // ---- previous key pairing ----

    [Fact] public void PreviousKeyOnly_Throws() { var d = BaseLogin(); d["Security:JwtPreviousSigningKey"] = Key32(0x22); AssertThrows(d); }
    [Fact] public void PreviousKidOnly_Throws() { var d = BaseLogin(); d["Security:Jwt:PreviousKeyId"] = "k0"; AssertThrows(d); }

    [Fact]
    public void PreviousSecretWithoutCurrentSecret_Throws()
    {
        var d = new Dictionary<string, string?>
        {
            ["ConnectionStrings:Bitosx"] = Conn,
            ["Security:JwtPreviousSigningKey"] = Key32(0x22),
            ["Security:Jwt:PreviousKeyId"] = "k0",
        };
        AssertThrows(d); // orphan previous secret, no current key
    }

    [Fact]
    public void ValidPreviousPair_LoginEnabled()
    {
        var d = BaseLogin();
        d["Security:JwtPreviousSigningKey"] = Key32(0x22);
        d["Security:Jwt:PreviousKeyId"] = "k0";
        Assert.True(LoginEnabled(d));
    }

    [Fact] public void MalformedPreviousKey_Throws() { var d = BaseLogin(); d["Security:JwtPreviousSigningKey"] = "@@bad@@"; d["Security:Jwt:PreviousKeyId"] = "k0"; AssertThrows(d); }
    [Fact] public void ShortPreviousKey_Throws() { var d = BaseLogin(); d["Security:JwtPreviousSigningKey"] = Convert.ToBase64String(new byte[16]); d["Security:Jwt:PreviousKeyId"] = "k0"; AssertThrows(d); }
    [Fact] public void PreviousKidEqualsCurrentKid_Throws() { var d = BaseLogin(); d["Security:JwtPreviousSigningKey"] = Key32(0x22); d["Security:Jwt:PreviousKeyId"] = "k1"; AssertThrows(d); }

    // ---- M-2: RefreshTokenOptions lifetime validation ----

    [Fact] public void DefaultLifetimes_LoginEnabled() => Assert.True(LoginEnabled(BaseLogin())); // no refresh config → 30d/90d defaults

    [Fact] public void ZeroIdle_Throws() { var d = BaseLogin(); d["Security:RefreshToken:IdleLifetimeSeconds"] = "0"; AssertThrows(d); }
    [Fact] public void NegativeIdle_Throws() { var d = BaseLogin(); d["Security:RefreshToken:IdleLifetimeSeconds"] = "-1"; AssertThrows(d); }
    [Fact] public void ZeroAbsolute_Throws() { var d = BaseLogin(); d["Security:RefreshToken:AbsoluteLifetimeSeconds"] = "0"; AssertThrows(d); }
    [Fact] public void NegativeAbsolute_Throws() { var d = BaseLogin(); d["Security:RefreshToken:AbsoluteLifetimeSeconds"] = "-1"; AssertThrows(d); }
    [Fact] public void HugeIdle_Throws() { var d = BaseLogin(); d["Security:RefreshToken:IdleLifetimeSeconds"] = long.MaxValue.ToString(); AssertThrows(d); }
    [Fact] public void HugeAbsolute_Throws() { var d = BaseLogin(); d["Security:RefreshToken:AbsoluteLifetimeSeconds"] = long.MaxValue.ToString(); AssertThrows(d); }

    [Fact]
    public void ReasonableCustomLifetimes_LoginEnabled()
    {
        var d = BaseLogin();
        d["Security:RefreshToken:IdleLifetimeSeconds"] = "1209600";  // 14 days
        d["Security:RefreshToken:AbsoluteLifetimeSeconds"] = "7776000"; // 90 days
        Assert.True(LoginEnabled(d));
    }
}
