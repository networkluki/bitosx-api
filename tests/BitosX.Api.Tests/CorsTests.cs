using System.Net;
using System.Net.Http.Headers;
using BitosX.Api.Security;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;

namespace BitosX.Api.Tests;

/// <summary>
/// Fail-closed validation of <c>Security:Cors</c> (unit) and the browser-facing behaviour of the CORS
/// policy over TestServer (integration): only the configured https origin gets CORS headers, with a
/// narrow method/header set, no credentials, and nothing at all when the feature is disabled.
/// </summary>
public sealed class BrowserCorsOptionsTests
{
    private const string P = "Security:Cors:";

    private static BrowserCorsOptions Bind(Dictionary<string, string?> d)
        => BrowserCorsOptions.Bind(new ConfigurationBuilder().AddInMemoryCollection(d).Build());

    private static void AssertRejected(string origins)
        => Assert.Throws<InvalidOperationException>(() => Bind(new() { [P + "AllowedOrigins"] = origins }));

    [Fact]
    public void Default_IsDisabled()
    {
        var o = Bind(new());
        Assert.False(o.Enabled);
        Assert.Empty(o.Origins);
        Assert.Equal(600, o.PreflightMaxAgeSeconds);
        Assert.Throws<InvalidOperationException>(() => o.BuildPolicy());
    }

    [Fact]
    public void ExactHttpsOrigins_Bind_InOrder()
    {
        var o = Bind(new() { [P + "AllowedOrigins"] = "https://vault.bitosx.se; https://bitosx.se" });
        Assert.True(o.Enabled);
        Assert.Equal(["https://vault.bitosx.se", "https://bitosx.se"], o.Origins);
    }

    [Fact]
    public void ExplicitPort_IsAccepted()
    {
        var o = Bind(new() { [P + "AllowedOrigins"] = "https://vault.bitosx.se:8443" });
        Assert.Equal(["https://vault.bitosx.se:8443"], o.Origins);
    }

    [Fact] public void Wildcard_Rejected() => AssertRejected("*");
    [Fact] public void SubdomainWildcard_Rejected() => AssertRejected("https://*.bitosx.se");
    [Fact] public void Http_Rejected() => AssertRejected("http://vault.bitosx.se");
    [Fact] public void HttpLoopback_Rejected() => AssertRejected("http://localhost:5173");
    [Fact] public void TrailingSlash_Rejected() => AssertRejected("https://vault.bitosx.se/");
    [Fact] public void Path_Rejected() => AssertRejected("https://vault.bitosx.se/verify-email");
    [Fact] public void Query_Rejected() => AssertRejected("https://vault.bitosx.se?x=1");
    [Fact] public void Fragment_Rejected() => AssertRejected("https://vault.bitosx.se#x");
    [Fact] public void UpperCase_Rejected() => AssertRejected("https://Vault.bitosx.se");
    [Fact] public void UserInfo_Rejected() => AssertRejected("https://user@vault.bitosx.se");
    [Fact] public void BareHost_Rejected() => AssertRejected("vault.bitosx.se");
    [Fact] public void OtherScheme_Rejected() => AssertRejected("ftp://vault.bitosx.se");
    [Fact] public void Duplicate_Rejected() => AssertRejected("https://vault.bitosx.se;https://vault.bitosx.se");
    [Fact] public void EmbeddedWhitespace_Rejected() => AssertRejected("https://vault bitosx.se");
    [Fact] public void TooLong_Rejected() => AssertRejected("https://" + new string('a', 300) + ".se");

    [Fact] public void NegativeMaxAge_Rejected() => Assert.Throws<InvalidOperationException>(() => Bind(new() { [P + "PreflightMaxAgeSeconds"] = "-1" }));
    [Fact] public void MaxAgeAboveOneDay_Rejected() => Assert.Throws<InvalidOperationException>(() => Bind(new() { [P + "PreflightMaxAgeSeconds"] = "86401" }));

    // Invalid config fails even when it would otherwise leave CORS disabled: a typo must be visible, not silently ignored.
    [Fact] public void InvalidMaxAge_FailsEvenWithoutOrigins() => Assert.Throws<InvalidOperationException>(() => Bind(new() { [P + "PreflightMaxAgeSeconds"] = "-5" }));

    [Fact]
    public void Policy_IsNarrow_And_NeverCredentialed()
    {
        var policy = Bind(new() { [P + "AllowedOrigins"] = "https://vault.bitosx.se", [P + "PreflightMaxAgeSeconds"] = "120" }).BuildPolicy();

        Assert.False(policy.AllowAnyOrigin);
        Assert.False(policy.AllowAnyMethod);
        Assert.False(policy.AllowAnyHeader);
        Assert.False(policy.SupportsCredentials);
        Assert.Equal(["https://vault.bitosx.se"], policy.Origins);
        Assert.Equal(["GET", "POST", "DELETE"], policy.Methods);
        Assert.Equal(["Authorization", "Content-Type", "Accept"], policy.Headers);
        Assert.Equal(["Retry-After", "X-Correlation-ID"], policy.ExposedHeaders);
        Assert.Equal(TimeSpan.FromSeconds(120), policy.PreflightMaxAge);
        Assert.True(policy.IsOriginAllowed("https://vault.bitosx.se"));
        Assert.False(policy.IsOriginAllowed("https://vault.bitosx.se.evil.example"));
        Assert.False(policy.IsOriginAllowed("http://vault.bitosx.se"));
    }
}

/// <summary>
/// Browser-visible behaviour over TestServer. The repository appsettings.json lists
/// https://vault.bitosx.se, so the default factory exercises the shipped configuration; the disabled
/// and invalid cases override Security:Cors:AllowedOrigins through host settings.
/// </summary>
public sealed class CorsEndpointTests : IClassFixture<WebApplicationFactory<Program>>
{
    private const string VaultOrigin = "https://vault.bitosx.se";
    private const string OtherOrigin = "https://attacker.example";

    private readonly WebApplicationFactory<Program> _factory;

    public CorsEndpointTests(WebApplicationFactory<Program> factory) => _factory = factory;

    private static HttpRequestMessage Preflight(string path, string origin, string method, string? requestHeaders = "content-type,authorization")
    {
        var req = new HttpRequestMessage(HttpMethod.Options, path);
        req.Headers.Add("Origin", origin);
        req.Headers.Add("Access-Control-Request-Method", method);
        if (requestHeaders is not null) req.Headers.Add("Access-Control-Request-Headers", requestHeaders);
        return req;
    }

    private static string? Header(HttpResponseMessage r, string name)
        => r.Headers.TryGetValues(name, out var v) ? string.Join(",", v) : null;

    private static WebApplicationFactory<Program> WithSetting(WebApplicationFactory<Program> f, string key, string value)
        => f.WithWebHostBuilder(b => b.UseSetting(key, value));

    [Fact]
    public async Task Preflight_FromVaultOrigin_IsAnsweredWithNarrowPolicy()
    {
        var resp = await _factory.CreateClient().SendAsync(Preflight("/v1/auth/login", VaultOrigin, "POST"));

        Assert.Equal(HttpStatusCode.NoContent, resp.StatusCode);
        Assert.Equal(VaultOrigin, Header(resp, "Access-Control-Allow-Origin"));
        var methods = Header(resp, "Access-Control-Allow-Methods")!;
        Assert.Contains("POST", methods);
        Assert.DoesNotContain("PUT", methods);
        var headers = Header(resp, "Access-Control-Allow-Headers")!;
        Assert.Contains("Authorization", headers, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Content-Type", headers, StringComparison.OrdinalIgnoreCase);
        Assert.Equal("600", Header(resp, "Access-Control-Max-Age"));
        Assert.Null(Header(resp, "Access-Control-Allow-Credentials"));
        // The preflight never reached an endpoint, but still carries the correlation id like every response.
        Assert.NotNull(Header(resp, "X-Correlation-ID"));
    }

    [Fact]
    public async Task Preflight_ForSessionRevoke_AllowsDelete()
    {
        var resp = await _factory.CreateClient().SendAsync(
            Preflight("/v1/account/sessions/11111111-2222-4333-8444-555555555555", VaultOrigin, "DELETE", "authorization"));

        Assert.Equal(HttpStatusCode.NoContent, resp.StatusCode);
        Assert.Equal(VaultOrigin, Header(resp, "Access-Control-Allow-Origin"));
        Assert.Contains("DELETE", Header(resp, "Access-Control-Allow-Methods")!);
    }

    // The framework answers the preflight for an allowed origin and lists what the policy permits; the
    // browser then refuses the real request because the header/method it wanted is missing from the list.
    [Fact]
    public async Task Preflight_WithDisallowedRequestHeader_DoesNotListIt()
    {
        var resp = await _factory.CreateClient().SendAsync(Preflight("/v1/auth/login", VaultOrigin, "POST", "x-custom-secret"));

        var headers = Header(resp, "Access-Control-Allow-Headers") ?? string.Empty;
        Assert.DoesNotContain("x-custom-secret", headers, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Preflight_WithDisallowedMethod_DoesNotListIt()
    {
        var resp = await _factory.CreateClient().SendAsync(Preflight("/v1/account/me", VaultOrigin, "PUT", null));

        var methods = Header(resp, "Access-Control-Allow-Methods") ?? string.Empty;
        Assert.DoesNotContain("PUT", methods, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("PATCH", methods, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task TwoOrigins_ResponseVariesByOrigin_AndEchoesOnlyTheCaller()
    {
        using var f = WithSetting(_factory, "Security:Cors:AllowedOrigins", "https://vault.bitosx.se;https://bitosx.se");
        var client = f.CreateClient();

        var req = new HttpRequestMessage(HttpMethod.Get, "/health");
        req.Headers.Add("Origin", "https://bitosx.se");
        var resp = await client.SendAsync(req);

        Assert.Equal("https://bitosx.se", Header(resp, "Access-Control-Allow-Origin"));
        Assert.Contains("Origin", Header(resp, "Vary") ?? string.Empty);
    }

    [Fact]
    public async Task Preflight_FromOtherOrigin_GetsNoCorsHeaders()
    {
        var resp = await _factory.CreateClient().SendAsync(Preflight("/v1/auth/login", OtherOrigin, "POST"));

        Assert.Null(Header(resp, "Access-Control-Allow-Origin"));
        Assert.Null(Header(resp, "Access-Control-Allow-Methods"));
        Assert.Null(Header(resp, "Access-Control-Allow-Headers"));
    }

    [Theory]
    [InlineData("https://vault.bitosx.se.attacker.example")]
    [InlineData("https://attackervault.bitosx.se")]
    [InlineData("http://vault.bitosx.se")]
    [InlineData("https://vault.bitosx.se:444")]
    [InlineData("null")]
    public async Task ActualRequest_FromLookalikeOrigin_GetsNoCorsHeaders(string origin)
    {
        var req = new HttpRequestMessage(HttpMethod.Get, "/health");
        req.Headers.Add("Origin", origin);
        var resp = await _factory.CreateClient().SendAsync(req);

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode); // the API still answers; the browser just may not read it
        Assert.Null(Header(resp, "Access-Control-Allow-Origin"));
    }

    [Fact]
    public async Task ActualRequest_FromVaultOrigin_ExposesOnlyTheListedHeaders()
    {
        var req = new HttpRequestMessage(HttpMethod.Get, "/health");
        req.Headers.Add("Origin", VaultOrigin);
        var resp = await _factory.CreateClient().SendAsync(req);

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Equal(VaultOrigin, Header(resp, "Access-Control-Allow-Origin"));
        var exposed = Header(resp, "Access-Control-Expose-Headers")!;
        Assert.Contains("Retry-After", exposed);
        Assert.Contains("X-Correlation-ID", exposed);
        Assert.Null(Header(resp, "Access-Control-Allow-Credentials"));
    }

    [Fact]
    public async Task RequestWithoutOrigin_IsUnaffected()
    {
        var resp = await _factory.CreateClient().GetAsync("/health");

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Null(Header(resp, "Access-Control-Allow-Origin"));
    }

    [Fact]
    public async Task Disabled_EmptyOriginList_EmitsNoCorsHeadersAtAll()
    {
        using var f = WithSetting(_factory, "Security:Cors:AllowedOrigins", "");
        var client = f.CreateClient();

        var pre = await client.SendAsync(Preflight("/v1/auth/login", VaultOrigin, "POST"));
        Assert.Null(Header(pre, "Access-Control-Allow-Origin"));
        Assert.Null(Header(pre, "Access-Control-Allow-Methods"));

        var req = new HttpRequestMessage(HttpMethod.Get, "/health");
        req.Headers.Add("Origin", VaultOrigin);
        var actual = await client.SendAsync(req);
        Assert.Equal(HttpStatusCode.OK, actual.StatusCode);
        Assert.Null(Header(actual, "Access-Control-Allow-Origin"));
    }

    [Fact]
    public void InvalidOrigin_FailsStartup()
    {
        using var f = WithSetting(_factory, "Security:Cors:AllowedOrigins", "http://vault.bitosx.se");
        var ex = Record.Exception(() => f.CreateClient());
        Assert.NotNull(ex);
        Assert.Contains("Security:Cors:AllowedOrigins", ex!.ToString());
    }

    [Fact]
    public void WildcardOrigin_FailsStartup()
    {
        using var f = WithSetting(_factory, "Security:Cors:AllowedOrigins", "*");
        Assert.NotNull(Record.Exception(() => f.CreateClient()));
    }
}
