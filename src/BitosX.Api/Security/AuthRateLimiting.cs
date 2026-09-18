using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Threading.RateLimiting;
using BitosX.Application.Accounts;
using BitosX.Contracts.Accounts;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace BitosX.Api.Security;

/// <summary>Holds the three process-local auth rate limiters (per-IP login, per-email login, per-IP refresh).</summary>
public sealed class AuthRateLimiters : IDisposable
{
    public BoundedRateLimiterCache LoginPerIp { get; }
    public BoundedRateLimiterCache LoginPerEmail { get; }
    public BoundedRateLimiterCache RefreshPerIp { get; }

    public AuthRateLimiters(PublicExposureHardeningOptions options, TimeProvider clock)
    {
        var idle = TimeSpan.FromMinutes(options.PartitionState.IdleExpirationMinutes);
        LoginPerIp = new BoundedRateLimiterCache(options.LoginPerIp, options.PartitionState.MaxIpPartitions, idle, clock);
        RefreshPerIp = new BoundedRateLimiterCache(options.RefreshPerIp, options.PartitionState.MaxIpPartitions, idle, clock);
        LoginPerEmail = new BoundedRateLimiterCache(options.LoginPerEmail, options.PartitionState.MaxEmailPartitions, idle, clock);
    }

    public void Dispose()
    {
        LoginPerIp.Dispose();
        RefreshPerIp.Dispose();
        LoginPerEmail.Dispose();
    }
}

/// <summary>
/// Phase 2D.1 HTTP rate limiting for the unauthenticated auth endpoints, applied as endpoint filters so
/// the limits sit on exactly the login/refresh routes. All controls are inert unless
/// <see cref="PublicExposureHardeningOptions.Enabled"/> is true. Rejections use one generic contract
/// (429 for rate limits, 503 for an unresolvable client IP in hardened mode) that reveals neither which
/// limiter fired nor any account/email/IP/token value.
/// </summary>
public static class AuthRateLimiting
{
    /// <summary>Binds + validates <c>Security:PublicExposureHardening</c> (fail-closed) and registers the limiters when enabled.</summary>
    public static IServiceCollection AddPublicExposureHardening(this IServiceCollection services, IConfiguration configuration)
    {
        var options = new PublicExposureHardeningOptions();
        configuration.GetSection(PublicExposureHardeningOptions.SectionName).Bind(options);
        options.Validate(); // fail startup on any invalid/out-of-range security value

        services.AddSingleton(options);
        if (options.Enabled)
        {
            services.TryAddSingleton(TimeProvider.System);
            services.AddSingleton<AuthRateLimiters>();
        }

        return services;
    }

    // ---- endpoint filters ----

    /// <summary>Per-IP login limit; also fails closed with 503 when no usable client IP can be resolved.</summary>
    public static async ValueTask<object?> LoginPerIpFilter(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
        => await PerIpAsync(context, next, static r => r.LoginPerIp);

    /// <summary>Per-IP refresh limit; same 503-on-unresolvable-IP behavior.</summary>
    public static async ValueTask<object?> RefreshPerIpFilter(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
        => await PerIpAsync(context, next, static r => r.RefreshPerIp);

    private static async ValueTask<object?> PerIpAsync(
        EndpointFilterInvocationContext context, EndpointFilterDelegate next, Func<AuthRateLimiters, BoundedRateLimiterCache> select)
    {
        var http = context.HttpContext;
        var options = http.RequestServices.GetRequiredService<PublicExposureHardeningOptions>();
        if (!options.Enabled)
        {
            return await next(context);
        }

        // Hardened mode: without a usable, trusted, non-loopback client IP we fail closed rather than
        // bucketing every caller under a shared/loopback key.
        if (!ClientIpResolver.TryResolveUsableClientIp(http, out var ipKey))
        {
            return ServiceUnavailable();
        }

        var limiters = http.RequestServices.GetRequiredService<AuthRateLimiters>();
        // Capacity exhaustion (new key, cache full, nothing idle) fails closed with 503 — never a shared
        // bucket and never a reset of an existing live limiter.
        if (!select(limiters).TryAcquire(ipKey, out var lease))
        {
            return ServiceUnavailable();
        }

        using (lease)
        {
            return lease.IsAcquired ? await next(context) : TooManyRequests(http, lease);
        }
    }

    /// <summary>
    /// Per-normalized-email login limit. Runs after model binding but before the expensive credential path,
    /// reusing the SAME <see cref="EmailNormalizer"/> as the login service. The partition key is
    /// SHA-256(UTF-8(normalizedEmail)) — a stable, non-plaintext identifier (not password hashing), so the
    /// email is never used or logged as the limiter key. Applies identically whether the account exists.
    /// </summary>
    public static async ValueTask<object?> LoginPerEmailFilter(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        var http = context.HttpContext;
        var options = http.RequestServices.GetRequiredService<PublicExposureHardeningOptions>();
        if (!options.Enabled)
        {
            return await next(context);
        }

        var request = context.Arguments.OfType<LoginRequest>().FirstOrDefault();
        // Invalid email syntax preserves the existing login contract (the per-IP + global limits cover it);
        // we do not fabricate a limiter key from malformed input.
        if (request is null || !EmailAddressValidator.IsValid(request.Email))
        {
            return await next(context);
        }

        var normalized = EmailNormalizer.Normalize(request.Email);
        var key = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(normalized)));

        var limiters = http.RequestServices.GetRequiredService<AuthRateLimiters>();
        if (!limiters.LoginPerEmail.TryAcquire(key, out var lease))
        {
            return ServiceUnavailable();
        }

        using (lease)
        {
            return lease.IsAcquired ? await next(context) : TooManyRequests(http, lease);
        }
    }

    // ---- generic rejection contracts (no limiter/account/IP/token disclosure) ----

    private static IResult TooManyRequests(HttpContext http, RateLimitLease lease)
    {
        if (lease.TryGetMetadata(MetadataName.RetryAfter, out var retryAfter))
        {
            var seconds = (int)Math.Ceiling(retryAfter.TotalSeconds);
            if (seconds > 0)
            {
                http.Response.Headers.RetryAfter = seconds.ToString(CultureInfo.InvariantCulture);
            }
        }

        return Results.Problem(
            statusCode: StatusCodes.Status429TooManyRequests,
            title: "Too Many Requests",
            detail: "Too many requests. Try again later.");
    }

    private static IResult ServiceUnavailable() => Results.Problem(
        statusCode: StatusCodes.Status503ServiceUnavailable,
        title: "Service unavailable",
        detail: "Service temporarily unavailable.");
}
