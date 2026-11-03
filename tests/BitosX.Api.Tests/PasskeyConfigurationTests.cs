using System.Net;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;

namespace BitosX.Api.Tests;

/// <summary>
/// Security:WebAuthn at startup: the shipped section starts in Production; an http origin, a localhost or IP RP ID,
/// or an RP ID that does not cover the origin refuses to start there (fail closed); Development/Testing accept
/// http://localhost:&lt;port&gt; with RP ID localhost for the local live stack; a half-configured section always fails.
/// </summary>
public sealed class PasskeyConfigurationTests
{
    private static readonly string TestJwtKey = Convert.ToBase64String(new byte[32]);
    private const string DummyConn = "Server=127.0.0.1;Port=3306;Database=x;User ID=x;Password=y";

    private static WebApplicationFactory<Program> Factory(string environment, Action<IDictionary<string, string?>>? settings = null)
        => new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseEnvironment(environment);
            var map = new Dictionary<string, string?>();
            settings?.Invoke(map);
            foreach (var kv in map)
            {
                builder.UseSetting(kv.Key, kv.Value);
            }
        });

    /// <summary>Login + Totp (Passkeys needs both) with hardening on, as Production requires.</summary>
    private static void EnablePasskeys(IDictionary<string, string?> s)
    {
        s["ConnectionStrings:Bitosx"] = DummyConn;
        s["Security:JwtSigningKey"] = TestJwtKey;
        s["Security:Jwt:KeyId"] = "k1";
        s["Security:TotpKey"] = Convert.ToBase64String(new byte[32]);
        s["Security:PublicExposureHardening:Enabled"] = "true";
    }

    private static string StartupError(WebApplicationFactory<Program> factory)
    {
        var ex = Record.Exception(() => factory.CreateClient());
        Assert.NotNull(ex);
        return ex!.ToString();
    }

    [Fact]
    public async Task Production_ShippedSection_Starts_AndServesOptionsForTheProductionRelyingParty()
    {
        using var f = Factory("Production", EnablePasskeys);
        var client = f.CreateClient();
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/health")).StatusCode);
        // Mapped (an unauthenticated list is 401, not 404).
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/v1/account/passkeys")).StatusCode);
    }

    [Theory]
    [InlineData("Security:WebAuthn:Origins:0", "http://vault.bitosx.se", "must be https://")]
    [InlineData("Security:WebAuthn:Origins:0", "http://localhost:8788", "must be https://")]
    [InlineData("Security:WebAuthn:Origins:0", "https://vault.bitosx.se/app", "exact origin")]
    [InlineData("Security:WebAuthn:Origins:0", "https://evil.example", "registrable suffix")]
    [InlineData("Security:WebAuthn:Origins:0", "https://203.0.113.7", "")]
    [InlineData("Security:WebAuthn:RelyingPartyId", "localhost", "Development/Testing-only")]
    [InlineData("Security:WebAuthn:RelyingPartyId", "127.0.0.1", "domain name")]
    [InlineData("Security:WebAuthn:RelyingPartyId", "se", "at least two labels")]
    [InlineData("Security:WebAuthn:RelyingPartyId", "Vault.BitosX.se", "lower-case")]
    [InlineData("Security:WebAuthn:RelyingPartyId", "", "RelyingPartyId is required")]
    [InlineData("Security:WebAuthn:RelyingPartyName", "", "RelyingPartyName")]
    public void Production_UnsafeOrIncompleteSection_FailsStartup(string key, string value, string expected)
    {
        using var f = Factory("Production", s =>
        {
            EnablePasskeys(s);
            s[key] = value;
        });
        var error = StartupError(f);
        Assert.Contains("Security:WebAuthn", error, StringComparison.Ordinal);
        Assert.Contains(expected, error, StringComparison.Ordinal);
    }

    [Fact]
    public void Production_HttpOrigin_FailsStartup_EvenWithoutADatabase()
    {
        using var f = Factory("Production", s => s["Security:WebAuthn:Origins:0"] = "http://vault.bitosx.se");
        Assert.Contains("Security:WebAuthn", StartupError(f), StringComparison.Ordinal);
    }

    [Fact]
    public void Staging_IsTreatedLikeProduction()
    {
        using var f = Factory("Staging", s =>
        {
            EnablePasskeys(s);
            s["Security:WebAuthn:RelyingPartyId"] = "localhost";
            s["Security:WebAuthn:Origins:0"] = "http://localhost:8788";
        });
        Assert.Contains("Security:WebAuthn", StartupError(f), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("Testing")]
    [InlineData("Development")]
    public async Task DevelopmentAndTesting_AcceptLocalhost_ForTheLiveStack(string environment)
    {
        using var f = Factory(environment, s =>
        {
            EnablePasskeys(s);
            s["Security:PublicExposureHardening:Enabled"] = "false";
            s["Security:WebAuthn:RelyingPartyId"] = "localhost";
            s["Security:WebAuthn:Origins:0"] = "http://localhost:8788";
        });
        var client = f.CreateClient();
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/v1/account/passkeys")).StatusCode);
    }

    [Theory]
    [InlineData("http://127.0.0.1:8788")] // WebAuthn needs a domain; loopback IPs are not valid RP IDs
    [InlineData("http://example.test:8788")]
    public void Testing_OnlyLocalhostMayBeHttp(string origin)
    {
        using var f = Factory("Testing", s =>
        {
            EnablePasskeys(s);
            s["Security:WebAuthn:RelyingPartyId"] = "localhost";
            s["Security:WebAuthn:Origins:0"] = origin;
        });
        Assert.Contains("Security:WebAuthn", StartupError(f), StringComparison.Ordinal);
    }

    [Fact]
    public async Task BlankSection_PasskeysOff_WithoutTotp_PasskeysOff()
    {
        using (var blank = Factory("Production", s =>
        {
            EnablePasskeys(s);
            s["Security:WebAuthn:RelyingPartyId"] = "";
            s["Security:WebAuthn:RelyingPartyName"] = "";
            s["Security:WebAuthn:Origins:0"] = "";
        }))
        {
            Assert.Equal(HttpStatusCode.NotFound, (await blank.CreateClient().GetAsync("/v1/account/passkeys")).StatusCode);
        }

        using var noTotp = Factory("Production", s =>
        {
            EnablePasskeys(s);
            s.Remove("Security:TotpKey");
        });
        Assert.Equal(HttpStatusCode.NotFound, (await noTotp.CreateClient().GetAsync("/v1/account/passkeys")).StatusCode);
    }
}
