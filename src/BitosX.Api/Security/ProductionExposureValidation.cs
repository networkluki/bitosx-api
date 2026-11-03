using System.Net;
using BitosX.Application.Accounts;
using Microsoft.AspNetCore.Hosting.Server.Features;

namespace BitosX.Api.Security;

/// <summary>
/// Fail-closed startup checks for the intended hardened production topology
/// (Internet → Cloudflare → Apache → loopback Kestrel). Runs only in the Production environment;
/// Development/Test are unaffected. It validates the application's OWN configuration model — it does not
/// reach into Kestrel internals — so a misconfiguration is visible and refuses to start rather than
/// silently exposing the service.
/// </summary>
public static class ProductionExposureValidation
{
    public static void Validate(IHostEnvironment environment, IConfiguration configuration, AccountCapabilities capabilities)
    {
        if (!environment.IsProduction())
        {
            return; // Development/Test may run with hardening disabled and any local listener.
        }

        // (1) Public-exposure hardening must be ON in Production when the Login capability OR the EmailVerification
        // capability is enabled: forgot/reset-password (and its rate limiters) ride on EmailVerification alone.
        if (capabilities.LoginEnabled || capabilities.EmailVerificationEnabled)
        {
            var hardeningEnabled = configuration.GetValue<bool>($"{PublicExposureHardeningOptions.SectionName}:Enabled");
            if (!hardeningEnabled)
            {
                throw new InvalidOperationException(
                    "Production with the Login or EmailVerification capability requires Security:PublicExposureHardening:Enabled = true " +
                    "(bounded Argon2 work is always active, but the per-IP/per-email/per-account/global rate limits and jitter must be enabled before public exposure).");
            }
        }

        // (2) Any repository-controlled Kestrel listener must bind to loopback only. Wildcard/public
        // binding is refused so Kestrel can never be directly Internet-reachable behind the proxy chain.
        foreach (var url in ConfiguredListenerUrls(configuration))
        {
            if (!IsLoopbackOnly(url))
            {
                throw new InvalidOperationException(
                    $"Production Kestrel listener '{url}' must bind to loopback only (127.0.0.1, [::1], or a local Unix socket). " +
                    "Wildcard/public bindings (0.0.0.0, [::], *, +, or a public address) are not permitted — Apache is the only permitted peer.");
            }
        }
    }

    /// <summary>Listener URLs the application can observe from its own configuration (Kestrel endpoints + the host `urls`).</summary>
    private static IEnumerable<string> ConfiguredListenerUrls(IConfiguration configuration)
    {
        foreach (var endpoint in configuration.GetSection("Kestrel:Endpoints").GetChildren())
        {
            var url = endpoint["Url"];
            if (!string.IsNullOrWhiteSpace(url))
            {
                foreach (var u in url.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                {
                    yield return u;
                }
            }
        }

        // ASPNETCORE_URLS / --urls surface here as the host "urls" setting.
        var urls = configuration["urls"] ?? configuration["ASPNETCORE_URLS"];
        if (!string.IsNullOrWhiteSpace(urls))
        {
            foreach (var u in urls.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                yield return u;
            }
        }
    }

    private static bool IsLoopbackOnly(string url)
    {
        BindingAddress address;
        try
        {
            address = BindingAddress.Parse(url);
        }
        catch (Exception)
        {
            return false; // unparseable listener → treat as unsafe (fail closed)
        }

        if (address.IsUnixPipe || address.IsNamedPipe)
        {
            return true; // local transport, not network-reachable
        }

        var host = address.Host;
        if (string.IsNullOrEmpty(host))
        {
            return false;
        }

        if (string.Equals(host, "localhost", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        // Reject "*", "+", "0.0.0.0", "[::]" and any public host; accept only loopback IPs.
        return IPAddress.TryParse(host, out var ip) && IPAddress.IsLoopback(ip);
    }
}
