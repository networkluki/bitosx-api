using System.Globalization;
using System.Threading.RateLimiting;

namespace BitosX.Api.Security;

/// <summary>
/// Endpoint metadata: apply this per-account limiter in <see cref="PerAccountRateLimitMiddleware"/>, i.e. after
/// authorization and BEFORE the endpoint binds (reads and deserializes) the request body.
/// </summary>
public sealed class PerAccountRateLimitMetadata
{
    public PerAccountRateLimitMetadata(Func<AuthRateLimiters, BoundedRateLimiterCache> select) => Select = select;

    public Func<AuthRateLimiters, BoundedRateLimiterCache> Select { get; }
}

/// <summary>
/// Runs per-account limiters for endpoints that carry <see cref="PerAccountRateLimitMetadata"/>. Registered after
/// <c>UseAuthorization</c>, so the identity is the validated JWT's <c>sub</c> (server-issued, never client input),
/// and before the endpoint executes, so a rejected request costs no body read: the envelope upload accepts up to
/// about 22 MB of JSON, which an endpoint filter would only see after it had been read and parsed. Inert unless
/// public-exposure hardening is enabled. The rejection contracts are the same generic ones as the endpoint
/// filters: 429 (+ Retry-After) when the bucket is empty, 503 when the limiter cannot key or track the caller.
/// </summary>
public sealed class PerAccountRateLimitMiddleware
{
    private readonly RequestDelegate _next;

    public PerAccountRateLimitMiddleware(RequestDelegate next) => _next = next;

    public async Task InvokeAsync(HttpContext context)
    {
        var metadata = context.GetEndpoint()?.Metadata.GetMetadata<PerAccountRateLimitMetadata>();
        var options = context.RequestServices.GetRequiredService<PublicExposureHardeningOptions>();
        if (metadata is null || !options.Enabled)
        {
            await _next(context);
            return;
        }

        if (!Guid.TryParse(context.User.FindFirst("sub")?.Value, out var accountId) || accountId == Guid.Empty)
        {
            await ServiceUnavailable().ExecuteAsync(context); // authorization should have refused already; never an unkeyed bucket
            return;
        }

        var limiters = context.RequestServices.GetRequiredService<AuthRateLimiters>();
        if (!metadata.Select(limiters).TryAcquire(accountId.ToString("N"), out var lease))
        {
            await ServiceUnavailable().ExecuteAsync(context);
            return;
        }

        using (lease)
        {
            if (!lease.IsAcquired)
            {
                await TooManyRequests(context, lease).ExecuteAsync(context);
                return;
            }
        }

        await _next(context);
    }

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

        return Results.Problem(statusCode: StatusCodes.Status429TooManyRequests, title: "Too Many Requests", detail: "Too many requests. Try again later.");
    }

    private static IResult ServiceUnavailable() => Results.Problem(
        statusCode: StatusCodes.Status503ServiceUnavailable, title: "Service unavailable", detail: "Service temporarily unavailable.");
}
