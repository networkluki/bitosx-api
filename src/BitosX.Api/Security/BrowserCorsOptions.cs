using BitosX.Api.Http;
using Microsoft.AspNetCore.Cors.Infrastructure;

namespace BitosX.Api.Security;

/// <summary>
/// Cross-origin access for the browser client(s) of this API — today the web account app at
/// <c>https://vault.bitosx.se</c>. Configured under <c>Security:Cors</c>; bound and validated once at
/// startup (fail-closed), and <b>inert unless at least one origin is listed</b>: with an empty
/// <see cref="AllowedOrigins"/> no CORS middleware runs and no CORS header is ever emitted, which is
/// the previous behaviour (the Avalonia desktop client is not a browser and needs none).
///
/// The policy is deliberately narrow and not configurable beyond the origin list and the preflight
/// cache lifetime:
/// <list type="bullet">
/// <item>exact <c>https://</c> origins only — no wildcard, no <c>http://</c>, no path, no port-less
/// guessing; a browser's <c>Origin</c> header must match byte for byte;</item>
/// <item>methods <c>GET</c>, <c>POST</c>, <c>DELETE</c> (the surface the web app uses);</item>
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

    private const int MaxOriginLength = 256;
    private const int MaxPreflightMaxAgeSeconds = 86_400;

    /// <summary>
    /// Semicolon-separated list of exact origins (same shape as <c>AllowedHosts</c>), e.g.
    /// <c>https://vault.bitosx.se</c>. Empty (the default) disables CORS entirely.
    /// </summary>
    public string AllowedOrigins { get; set; } = string.Empty;

    /// <summary>How long a browser may cache a preflight answer (<c>Access-Control-Max-Age</c>), 0..86400 s.</summary>
    public int PreflightMaxAgeSeconds { get; set; } = 600;

    public static readonly string[] AllowedMethods = ["GET", "POST", "DELETE"];
    public static readonly string[] AllowedHeaders = ["Authorization", "Content-Type", "Accept"];
    public static readonly string[] ExposedHeaders = ["Retry-After", CorrelationIdMiddleware.HeaderName];

    /// <summary>The validated origin list (populated by <see cref="Validate"/>).</summary>
    public IReadOnlyList<string> Origins { get; private set; } = [];

    public bool Enabled => Origins.Count > 0;

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

        var origins = new List<string>();
        foreach (var raw in (AllowedOrigins ?? string.Empty).Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var origin = ValidateOrigin(raw);
            if (origins.Contains(origin, StringComparer.Ordinal))
            {
                throw new InvalidOperationException($"{SectionName}:AllowedOrigins lists '{origin}' more than once.");
            }
            origins.Add(origin);
        }

        Origins = origins.AsReadOnly();
    }

    /// <summary>
    /// An allowed origin is exactly <c>https://host[:port]</c>, in lowercase, with nothing else: no
    /// wildcard, no <c>http://</c> (also not for loopback — the web app is tested against a mock, not a
    /// plaintext origin), no userinfo, no path (not even a trailing slash), no query, no fragment.
    /// </summary>
    private static string ValidateOrigin(string origin)
    {
        if (origin.Length > MaxOriginLength || origin.Any(char.IsWhiteSpace) || origin.Any(char.IsControl))
        {
            throw new InvalidOperationException($"{SectionName}:AllowedOrigins contains an origin that is too long or contains whitespace/control characters.");
        }
        if (origin.Contains('*'))
        {
            throw new InvalidOperationException($"{SectionName}:AllowedOrigins must list exact origins; wildcards are not permitted ('{origin}').");
        }
        if (!Uri.TryCreate(origin, UriKind.Absolute, out var uri) || !string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.Ordinal))
        {
            throw new InvalidOperationException($"{SectionName}:AllowedOrigins entry '{origin}' must be an absolute https:// origin.");
        }
        if (uri.UserInfo.Length > 0 || string.IsNullOrEmpty(uri.Host))
        {
            throw new InvalidOperationException($"{SectionName}:AllowedOrigins entry '{origin}' must not carry userinfo and must name a host.");
        }

        // The canonical serialisation of scheme + host[:port] is lowercase and carries no path, query
        // or fragment. Requiring the configured string to equal it byte for byte rules out a trailing
        // slash, a path, uppercase letters and anything a browser would never send in Origin.
        var canonical = uri.GetLeftPart(UriPartial.Authority);
        if (!string.Equals(origin, canonical, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"{SectionName}:AllowedOrigins entry '{origin}' must be written exactly as '{canonical}' (lowercase, no path, no trailing slash).");
        }

        return origin;
    }

    /// <summary>The single CORS policy registered for the browser client(s). Requires a validated, enabled instance.</summary>
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
}
