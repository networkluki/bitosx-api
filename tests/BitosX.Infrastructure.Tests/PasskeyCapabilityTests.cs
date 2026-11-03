using System.Security.Cryptography;
using BitosX.Application.Abstractions.Persistence;
using BitosX.Application.Passkeys;
using BitosX.Infrastructure.Accounts;
using BitosX.Infrastructure.Passkeys;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace BitosX.Infrastructure.Tests;

/// <summary>The Passkeys capability: Login + Totp + a valid Security:WebAuthn section; validated whenever configured.</summary>
public sealed class PasskeyCapabilityTests
{
    private const string DummyConn = "Server=127.0.0.1;Port=3306;Database=bitosx;User ID=x;Password=y";

    private static IConfiguration Config(bool totp = true, bool webAuthn = true, Action<Dictionary<string, string?>>? tweak = null)
    {
        var d = new Dictionary<string, string?>
        {
            ["ConnectionStrings:Bitosx"] = DummyConn,
            ["Security:JwtSigningKey"] = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),
            ["Security:Jwt:KeyId"] = "k1",
        };
        if (totp) d["Security:TotpKey"] = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        if (webAuthn)
        {
            d["Security:WebAuthn:RelyingPartyId"] = "vault.bitosx.se";
            d["Security:WebAuthn:RelyingPartyName"] = "BitosX";
            d["Security:WebAuthn:Origins:0"] = "https://vault.bitosx.se";
        }

        tweak?.Invoke(d);
        return new ConfigurationBuilder().AddInMemoryCollection(d).Build();
    }

    [Fact]
    public void Detect_LoginTotpAndSection_PasskeysOn_MissingAnyPiece_Off()
    {
        Assert.True(AccountsServiceCollectionExtensions.DetectCapabilities(Config()).PasskeysEnabled);
        Assert.False(AccountsServiceCollectionExtensions.DetectCapabilities(Config(totp: false)).PasskeysEnabled);
        Assert.False(AccountsServiceCollectionExtensions.DetectCapabilities(Config(webAuthn: false)).PasskeysEnabled);
        Assert.False(AccountsServiceCollectionExtensions.DetectCapabilities(Config(tweak: d => d.Remove("ConnectionStrings:Bitosx"))).PasskeysEnabled);
    }

    [Fact]
    public void Detect_InvalidSection_Throws_EvenWithoutTotpOrDatabase()
    {
        Assert.Throws<InvalidOperationException>(() => AccountsServiceCollectionExtensions.DetectCapabilities(
            Config(totp: false, tweak: d => d["Security:WebAuthn:Origins:0"] = "http://vault.bitosx.se")));
        Assert.Throws<InvalidOperationException>(() => AccountsServiceCollectionExtensions.DetectCapabilities(
            Config(tweak: d => { d.Remove("ConnectionStrings:Bitosx"); d["Security:WebAuthn:RelyingPartyName"] = ""; })));
        // localhost is a Development/Testing setting.
        var local = Config(tweak: d => { d["Security:WebAuthn:RelyingPartyId"] = "localhost"; d["Security:WebAuthn:Origins:0"] = "http://localhost:8788"; });
        Assert.Throws<InvalidOperationException>(() => AccountsServiceCollectionExtensions.DetectCapabilities(local));
        Assert.True(AccountsServiceCollectionExtensions.DetectCapabilities(local, allowDevelopmentOnlySettings: true).PasskeysEnabled);
    }

    [Fact]
    public void Origins_AcceptAListOrOneSeparatedString_Canonicalized()
    {
        var options = WebAuthnConfiguration.BindAndValidate(Config(tweak: d =>
        {
            d.Remove("Security:WebAuthn:Origins:0");
            d["Security:WebAuthn:Origins"] = "https://vault.bitosx.se; https://beta.vault.bitosx.se:8443";
        }), allowLocalhost: false)!;
        Assert.Equal(["https://vault.bitosx.se", "https://beta.vault.bitosx.se:8443"], options.Origins);
        Assert.Null(WebAuthnConfiguration.BindAndValidate(Config(webAuthn: false), allowLocalhost: false));
    }

    [Fact]
    public void AddBitosxPasskeys_RegistersTheRelyingPartyAndServices_RefusesWithoutSection()
    {
        var services = new ServiceCollection();
        services.AddBitosxPasskeys(Config());
        Assert.Contains(services, s => s.ServiceType == typeof(IWebAuthnRelyingParty));
        Assert.Contains(services, s => s.ServiceType == typeof(IPasskeyLoginService));
        Assert.Contains(services, s => s.ServiceType == typeof(IPasskeyManagementService));
        Assert.Contains(services, s => s.ServiceType == typeof(PasskeyAvailability) && ((PasskeyAvailability)s.ImplementationInstance!).Enabled);

        Assert.Throws<InvalidOperationException>(() => new ServiceCollection().AddBitosxPasskeys(Config(webAuthn: false)));
    }

    [Fact]
    public void AddBitosxLogin_RegistersPasskeyPersistence_WithoutTheCapability()
    {
        var services = new ServiceCollection();
        services.AddBitosxLogin(Config(totp: false, webAuthn: false), DummyConn);
        Assert.Contains(services, s => s.ServiceType == typeof(IPasskeyStore));
        Assert.Contains(services, s => s.ServiceType == typeof(IWebAuthnChallengeStore));
        Assert.DoesNotContain(services, s => s.ServiceType == typeof(IWebAuthnRelyingParty));
    }
}
