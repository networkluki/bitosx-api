using BitosX.Api.Http;
using Microsoft.AspNetCore.Cors.Infrastructure;

namespace BitosX.Api.Security;

/// <summary>
/// Cross-origin access for the browser client(s) of this API — the web account app at
/// <c>https://vault.bitosx.se</c>, plus the product page at <c>https://bitosx.se</c>, which may read only
/// <c>GET /health</c> and <c>GET /version</c>. Configured under <c>Security:Cors</c>; bound and validated once
/// at startup (fail-closed), and <b>inert unless at least one origin is listed</b>: with both
/// <see cref="AllowedOrigins"/> and <see cref="StatusPageOrigins"/> empty no CORS middleware runs and no
/// CORS header is ever emitted (the Avalonia desktop client is not a browser and needs none).
///
/// Two policies, both deliberately narrow and not configurable beyond the origin lists and the preflight
/// cache lifetime:
/// <list type="bullet">
/// <item><see cref="PolicyName"/> (the default for every endpoint): the <see cref="AllowedOrigins"/>;</item>
/// <item><see cref="StatusPolicyName"/> (only <c>/health</c> and <c>/version</c>): the
/// <see cref="AllowedOrigins"/> plus the <see cref="StatusPageOrigins"/>, method <c>GET</c> only. A status-page
/// origin gets no CORS header from any other endpoint.</item>
/// </list>
/// Common to both:
/// <list type="bullet">
/// <item>exact <c>https://</c> origins only — no wildcard, no <c>http://</c>, no path, no port-less
/// guessing; a browser's <c>Origin</c> header must match byte for byte;</item>
/// <item>methods <c>GET</c>, <c>POST</c>, <c>PUT</c>, <c>DELETE</c> (the surface the web app uses; <c>PUT</c> is
/// the envelope upload <c>PUT /v1/sync/envelope</c>);</item>
/// <item>request headers <c>Authorization</c>, <c>Content-Type</c>, <c>Accept</c>;</item>
/// <item>exposed response headers <c>Retry-After</c> and <c>X-Correlation-ID</c>;</item>
/// <item><b>no</b> <c>Access-Control-Allow-Credentials</c>: the web app authenticates with a bearer token
/// it sends itself, never with cookies, so credentialed cross-site requests stay impossible.</item>
/// </list>
/// CORS is a browser-side control that decides which web origins may read responses; it does not
/// authenticate anything. The zero-knowledge boundary, rate limits and token validation are unchanged.
/// </summary>
public sealed class BrowserCorsOptions
{
    public const string SectionName = "Security:Cors";
    public const string PolicyName = "BitosXBrowserClients";
    public const string StatusPolicyName = "BitosXStatusPage";

    private const int MaxOriginLength = 256;
    private const int MaxPreflightMaxAgeSeconds = 86_400;

    /// <summary>
    /// Semicolon-separated list of exact origins (same shape as <c>AllowedHosts</c>), e.g.
    /// <c>https://vault.bitosx.se</c>. Empty (the default) disables CORS entirely.
    /// </summary>
    public string AllowedOrigins { get; set; } = string.Empty;

    /// <summary>
    /// Semicolon-separated list of exact origins that may read only <c>GET /health</c> and <c>GET /version</c>
    /// (the product page's live status badge), e.g. <c>https://bitosx.se</c>. Same validation as
    /// <see cref="AllowedOrigins"/>. Empty (the default) adds no status-page origin.
    /// </summary>
    public string StatusPageOrigins { get; set; } = string.Empty;

    /// <summary>How long a browser may cache a preflight answer (<c>Access-Control-Max-Age</c>), 0..86400 s.</summary>
    public int PreflightMaxAgeSeconds { get; set; } = 600;

    public static readonly string[] AllowedMethods = ["GET", "POST", "PUT", "DELETE"];
    public static readonly string[] StatusMethods = ["GET"];
    public static readonly string[] AllowedHeaders = ["Authorization", "Content-Type", "Accept"];
    public static readonly string[] ExposedHeaders = ["Retry-After", CorrelationIdMiddleware.HeaderName];

    /// <summary>The validated origin list (populated by <see cref="Validate"/>).</summary>
    public IReadOnlyList<string> Origins { get; private set; } = [];

    /// <summary>The validated status-page origin list (populated by <see cref="Validate"/>).</summary>
    public IReadOnlyList<string> StatusOrigins { get; private set; } = [];

    /// <summary>The browser-client policy exists (at least one <see cref="AllowedOrigins"/> entry).</summary>
    public bool Enabled => Origins.Count > 0;

    /// <summary>The status-endpoint policy exists (at least one origin of either list).</summary>
    public bool StatusPolicyEnabled => Origins.Count > 0 || StatusOrigins.Count > 0;

    /// <summary>Any CORS policy is configured, so the CORS middleware must run.</summary>
    public bool AnyEnabled => StatusPolicyEnabled;

    /// <summary>Binds <c>Security:Cors</c> and validates it fail-closed. Throws on any invalid value.</summary>
    public static BrowserCorsOptions Bind(IConfiguration configuration)
    {
        var options = new BrowserCorsOptions();
        configuration.GetSection(SectionName).Bind(options);
        options.Validate();
        return options;
    }

    /// <summary>Fail-closed validation of every value. Throws <see cref="InvalidOperationException"/> on the first problem.</summary>
    public void Validate()
    {
        if (PreflightMaxAgeSeconds < 0 || PreflightMaxAgeSeconds > MaxPreflightMaxAgeSeconds)
        {
            throw new InvalidOperationException($"{SectionName}:PreflightMaxAgeSeconds must be between 0 and {MaxPreflightMaxAgeSeconds}.");
        }

        Origins = ParseOrigins(AllowedOrigins, "AllowedOrigins");
        StatusOrigins = ParseOrigins(StatusPageOrigins, "StatusPageOrigins");
    }

    private static IReadOnlyList<string> ParseOrigins(string? list, string key)
    {
        var origins = new List<string>();
        foreach (var raw in (list ?? string.Empty).Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var origin = ValidateOrigin(raw, key);
            if (origins.Contains(origin, StringComparer.Ordinal))
            {
                throw new InvalidOperationException($"{SectionName}:{key} lists '{origin}' more than once.");
            }
            origins.Add(origin);
        }

        return origins.AsReadOnly();
    }

    /// <summary>
    /// An allowed origin is exactly <c>https://host[:port]</c>, in lowercase, with nothing else: no
    /// wildcard, no <c>http://</c> (also not for loopback — the web app is tested against a mock, not a
    /// plaintext origin), no userinfo, no path (not even a trailing slash), no query, no fragment.
    /// </summary>
    private static string ValidateOrigin(string origin, string key)
    {
        if (origin.Length > MaxOriginLength || origin.Any(char.IsWhiteSpace) || origin.Any(char.IsControl))
        {
            throw new InvalidOperationException($"{SectionName}:{key} contains an origin that is too long or contains whitespace/control characters.");
        }
        if (origin.Contains('*'))
        {
            throw new InvalidOperationException($"{SectionName}:{key} must list exact origins; wildcards are not permitted ('{origin}').");
        }
        if (!Uri.TryCreate(origin, UriKind.Absolute, out var uri) || !string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.Ordinal))
        {
            throw new InvalidOperationException($"{SectionName}:{key} entry '{origin}' must be an absolute https:// origin.");
        }
        if (uri.UserInfo.Length > 0 || string.IsNullOrEmpty(uri.Host))
        {
            throw new InvalidOperationException($"{SectionName}:{key} entry '{origin}' must not carry userinfo and must name a host.");
        }

        // The canonical serialisation of scheme + host[:port] is lowercase and carries no path, query
        // or fragment. Requiring the configured string to equal it byte for byte rules out a trailing
        // slash, a path, uppercase letters and anything a browser would never send in Origin.
        var canonical = uri.GetLeftPart(UriPartial.Authority);
        if (!string.Equals(origin, canonical, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"{SectionName}:{key} entry '{origin}' must be written exactly as '{canonical}' (lowercase, no path, no trailing slash).");
        }

        return origin;
    }

    /// <summary>The CORS policy for the browser client(s), the default for every endpoint. Requires a validated, enabled instance.</summary>
    public CorsPolicy BuildPolicy()
    {
        if (!Enabled)
        {
            throw new InvalidOperationException("CORS is not enabled: no allowed origin is configured.");
        }

        var policy = new CorsPolicyBuilder()
            .WithOrigins([.. Origins])
            .WithMethods(AllowedMethods)
            .WithHeaders(AllowedHeaders)
            .WithExposedHeaders(ExposedHeaders)
            .SetPreflightMaxAge(TimeSpan.FromSeconds(PreflightMaxAgeSeconds))
            .DisallowCredentials()
            .Build();

        return policy;
    }

    /// <summary>
    /// The CORS policy for <c>GET /health</c> and <c>GET /version</c> only: every browser-client origin plus the
    /// status-page origins, <c>GET</c> only, the same request-header list as the browser-client policy (the
    /// endpoints ignore them; a web-app request carrying <c>Authorization</c> must not fail its preflight), no
    /// credentials.
    /// </summary>
    public CorsPolicy BuildStatusPolicy()
    {
        if (!StatusPolicyEnabled)
        {
            throw new InvalidOperationException("The status CORS policy is not enabled: no origin is configured.");
        }

        return new CorsPolicyBuilder()
            .WithOrigins([.. Origins.Concat(StatusOrigins).Distinct(StringComparer.Ordinal)])
            .WithMethods(StatusMethods)
            .WithHeaders(AllowedHeaders)
            .WithExposedHeaders(ExposedHeaders)
            .SetPreflightMaxAge(TimeSpan.FromSeconds(PreflightMaxAgeSeconds))
            .DisallowCredentials()
            .Build();
    }
}
