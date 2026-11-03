using System.Net;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;

namespace BitosX.Api.Tests;

/// <summary>
/// Phase 2D.3 public-exposure gating: OpenAPI is Development-only, and the Production environment fails
/// closed on an unsafe posture (Login without hardening, or a wildcard/public Kestrel listener). Uses
/// TestServer (no real network); the listener checks read the application's own configuration.
/// </summary>
public sealed class ProductionExposureTests
{
    // Obviously test-only: 32 zero bytes is a valid (>=32-byte) Base64 signing key for enabling Login.
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

    private static void EnableLogin(IDictionary<string, string?> s)
    {
        s["ConnectionStrings:Bitosx"] = DummyConn;
        s["Security:JwtSigningKey"] = TestJwtKey;
        s["Security:Jwt:KeyId"] = "k1";
    }

    private static string StartupError(WebApplicationFactory<Program> factory)
    {
        var ex = Record.Exception(() => factory.CreateClient());
        Assert.NotNull(ex);
        return ex!.ToString();
    }

    // ---- OpenAPI gating ----

    [Fact]
    public async Task OpenApi_MappedInDevelopment()
    {
        using var f = Factory("Development");
        var resp = await f.CreateClient().GetAsync("/openapi/v1.json");
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    [Fact]
    public async Task OpenApi_NotMappedInProduction_Returns404()
    {
        using var f = Factory("Production");
        var resp = await f.CreateClient().GetAsync("/openapi/v1.json");
        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode); // normal not-found, not a document
    }

    [Fact]
    public async Task Production_InfrastructureEndpoints_StillAvailable()
    {
        using var f = Factory("Production");
        Assert.Equal(HttpStatusCode.OK, (await f.CreateClient().GetAsync("/health")).StatusCode);
    }

    // ---- production hardening startup gate ----

    [Fact]
    public void Production_LoginEnabled_HardeningDisabled_FailsStartup()
    {
        using var f = Factory("Production", EnableLogin); // hardening left disabled (default)
        Assert.Contains("PublicExposureHardening", StartupError(f), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Production_LoginEnabled_HardeningEnabled_Starts_AndMapsAuthSurface()
    {
        using var f = Factory("Production", s =>
        {
            EnableLogin(s);
            s["Security:PublicExposureHardening:Enabled"] = "true";
        });
        var client = f.CreateClient();

        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/health")).StatusCode);
        // Protected account surface is mapped (unauthenticated → 401, never 404) even in Production.
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/v1/account/me")).StatusCode);
    }

    private static void EnableVerification(IDictionary<string, string?> s)
    {
        s["ConnectionStrings:Bitosx"] = DummyConn;
        s["Security:EmailVerificationPepper"] = "test-pepper-value-please-long-random";
        s["Security:EmailOutboxKey"] = Convert.ToBase64String(new byte[32]);
        s["Email:FromAddress"] = "bitosx@example.com";
        s["Email:PublicBaseUrl"] = "https://vault.bitosx.se";
    }

    [Fact]
    public void Production_EmailVerificationOnly_HardeningDisabled_FailsStartup()
    {
        // No JWT key (Login off): forgot/reset-password are still public and their limiters need hardening.
        using var f = Factory("Production", EnableVerification);
        Assert.Contains("PublicExposureHardening", StartupError(f), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Production_EmailVerificationOnly_HardeningEnabled_Starts()
    {
        using var f = Factory("Production", s =>
        {
            EnableVerification(s);
            s["Security:PublicExposureHardening:Enabled"] = "true";
        });
        Assert.Equal(HttpStatusCode.OK, (await f.CreateClient().GetAsync("/health")).StatusCode);
    }

    [Theory]
    [InlineData("")]
    [InlineData("http://localhost:5173")] // loopback http is a Development/Testing convenience only
    [InlineData("vault.bitosx.se")]
    public void Production_EmailVerification_WithoutAnHttpsPublicBaseUrl_FailsStartup(string url)
    {
        using var f = Factory("Production", s =>
        {
            EnableVerification(s);
            s["Security:PublicExposureHardening:Enabled"] = "true";
            s["Email:PublicBaseUrl"] = url;
        });
        Assert.Contains("Email:PublicBaseUrl", StartupError(f), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Development_EmailVerification_LoopbackHttpPublicBaseUrl_Starts()
    {
        using var f = Factory("Development", s =>
        {
            EnableVerification(s);
            s["Email:PublicBaseUrl"] = "http://localhost:5173";
        });
        Assert.Equal(HttpStatusCode.OK, (await f.CreateClient().GetAsync("/health")).StatusCode);
    }

    [Fact]
    public async Task Production_LoginDisabled_DoesNotRequireHardening()
    {
        using var f = Factory("Production"); // no connection/JWT → Login disabled → hardening not required
        Assert.Equal(HttpStatusCode.OK, (await f.CreateClient().GetAsync("/health")).StatusCode);
    }

    // ---- Kestrel listener validation (repository-controlled config) ----

    [Fact]
    public async Task Production_LoopbackListener_Accepted()
    {
        using var f = Factory("Production", s => s["Kestrel:Endpoints:Http:Url"] = "http://127.0.0.1:5080");
        Assert.Equal(HttpStatusCode.OK, (await f.CreateClient().GetAsync("/health")).StatusCode);
    }

    [Theory]
    [InlineData("http://0.0.0.0:5080")]
    [InlineData("http://[::]:5080")]
    [InlineData("http://*:5080")]
    [InlineData("http://203.0.113.10:5080")]
    public void Production_WildcardOrPublicListener_FailsStartup(string url)
    {
        using var f = Factory("Production", s => s["Kestrel:Endpoints:Http:Url"] = url);
        Assert.Contains("loopback", StartupError(f), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Production_MalformedListener_FailsStartup()
    {
        using var f = Factory("Production", s => s["Kestrel:Endpoints:Http:Url"] = "::not-a-valid-url::");
        Assert.Contains("loopback", StartupError(f), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Development_WildcardListener_Allowed()
    {
        // Development/Test are not subject to the production loopback rule.
        using var f = Factory("Development", s => s["Kestrel:Endpoints:Http:Url"] = "http://0.0.0.0:5080");
        Assert.Equal(HttpStatusCode.OK, (await f.CreateClient().GetAsync("/health")).StatusCode);
    }
}
