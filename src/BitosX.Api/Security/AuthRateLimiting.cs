using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Threading.RateLimiting;
using BitosX.Application.Accounts;
using BitosX.Application.Mfa;
using BitosX.Contracts.Accounts;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace BitosX.Api.Security;

/// <summary>
/// Holds the process-local auth limiters: per-IP login, per-email login, per-IP refresh (all partitioned,
/// 2D.1), plus the single process-wide login budget (unpartitioned, 2D.2).
/// </summary>
public sealed class AuthRateLimiters : IDisposable
{
    public BoundedRateLimiterCache LoginPerIp { get; }
    public BoundedRateLimiterCache LoginPerEmail { get; }
    public BoundedRateLimiterCache RefreshPerIp { get; }

    /// <summary>Envelope writes, partitioned by account id (an authenticated, server-issued identity — never client input).</summary>
    public BoundedRateLimiterCache SyncWritePerAccount { get; }

    /// <summary>Forgot/reset-password, partitioned by trusted client IP.</summary>
    public BoundedRateLimiterCache PasswordResetPerIp { get; }

    /// <summary>Forgot-password, partitioned by SHA-256(normalized email) — the same key scheme as <see cref="LoginPerEmail"/>.</summary>
    public BoundedRateLimiterCache PasswordResetPerEmail { get; }

    /// <summary>Account deletion attempts, partitioned by the authenticated account id.</summary>
    public BoundedRateLimiterCache AccountDeletePerAccount { get; }

    /// <summary>Password change while signed in, partitioned by the authenticated account id.</summary>
    public BoundedRateLimiterCache PasswordChangePerAccount { get; }

    /// <summary>Second sign-in step, partitioned by trusted client IP.</summary>
    public BoundedRateLimiterCache MfaPerIp { get; }

    /// <summary>Second sign-in step, partitioned by the account the challenge token resolves to.</summary>
    public BoundedRateLimiterCache MfaPerAccount { get; }

    /// <summary>TOTP management, partitioned by the authenticated account id.</summary>
    public BoundedRateLimiterCache TotpManagePerAccount { get; }

    /// <summary>One process-wide token bucket shared across all IPs and all accounts/emails (no partition key).</summary>
    public TokenBucketRateLimiter GlobalLoginBudget { get; }

    public AuthRateLimiters(PublicExposureHardeningOptions options, TimeProvider clock)
    {
        var idle = TimeSpan.FromMinutes(options.PartitionState.IdleExpirationMinutes);
        LoginPerIp = new BoundedRateLimiterCache(options.LoginPerIp, options.PartitionState.MaxIpPartitions, idle, clock);
        RefreshPerIp = new BoundedRateLimiterCache(options.RefreshPerIp, options.PartitionState.MaxIpPartitions, idle, clock);
        LoginPerEmail = new BoundedRateLimiterCache(options.LoginPerEmail, options.PartitionState.MaxEmailPartitions, idle, clock);
        SyncWritePerAccount = new BoundedRateLimiterCache(options.SyncWritePerAccount, options.PartitionState.MaxEmailPartitions, idle, clock);
        PasswordResetPerIp = new BoundedRateLimiterCache(options.PasswordResetPerIp, options.PartitionState.MaxIpPartitions, idle, clock);
        PasswordResetPerEmail = new BoundedRateLimiterCache(options.PasswordResetPerEmail, options.PartitionState.MaxEmailPartitions, idle, clock);
        AccountDeletePerAccount = new BoundedRateLimiterCache(options.AccountDeletePerAccount, options.PartitionState.MaxEmailPartitions, idle, clock);
        PasswordChangePerAccount = new BoundedRateLimiterCache(options.PasswordChangePerAccount, options.PartitionState.MaxEmailPartitions, idle, clock);
        MfaPerIp = new BoundedRateLimiterCache(options.MfaPerIp, options.PartitionState.MaxIpPartitions, idle, clock);
        MfaPerAccount = new BoundedRateLimiterCache(options.MfaPerAccount, options.PartitionState.MaxEmailPartitions, idle, clock);
        TotpManagePerAccount = new BoundedRateLimiterCache(options.TotpManagePerAccount, options.PartitionState.MaxEmailPartitions, idle, clock);
        GlobalLoginBudget = new TokenBucketRateLimiter(new TokenBucketRateLimiterOptions
        {
            TokenLimit = options.GlobalLoginBudget.TokenLimit,
            TokensPerPeriod = options.GlobalLoginBudget.TokensPerPeriod,
            ReplenishmentPeriod = TimeSpan.FromSeconds(options.GlobalLoginBudget.ReplenishmentSeconds),
            AutoReplenishment = true,
            QueueLimit = 0,
            QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
        });
    }

    public void Dispose()
    {
        LoginPerIp.Dispose();
        RefreshPerIp.Dispose();
        LoginPerEmail.Dispose();
        SyncWritePerAccount.Dispose();
        PasswordResetPerIp.Dispose();
        PasswordResetPerEmail.Dispose();
        AccountDeletePerAccount.Dispose();
        PasswordChangePerAccount.Dispose();
        MfaPerIp.Dispose();
        MfaPerAccount.Dispose();
        TotpManagePerAccount.Dispose();
        GlobalLoginBudget.Dispose();
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
        services.TryAddSingleton(TimeProvider.System);
        // Jitter is always registered but no-ops when hardening is disabled (the endpoint always resolves it).
        services.AddSingleton<ILoginResponseJitter, LoginResponseJitter>();
        // Per-account bound on the second sign-in step (no-op when hardening is disabled).
        services.AddSingleton<IMfaAttemptLimiter, MfaAccountAttemptLimiter>();
        if (options.Enabled)
        {
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

    /// <summary>Per-IP second-sign-in-step limit; same 503-on-unresolvable-IP behavior.</summary>
    public static async ValueTask<object?> MfaPerIpFilter(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
        => await PerIpAsync(context, next, static r => r.MfaPerIp);

    /// <summary>Per-IP forgot/reset-password limit; same 503-on-unresolvable-IP behavior.</summary>
    public static async ValueTask<object?> PasswordResetPerIpFilter(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
        => await PerIpAsync(context, next, static r => r.PasswordResetPerIp);

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

    /// <summary>Per-account limit on TOTP management calls (same keying as the sync write limiter).</summary>
    public static async ValueTask<object?> TotpManagePerAccountFilter(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
        => await PerAccountAsync(context, next, static r => r.TotpManagePerAccount);

    /// <summary>Per-account limit on password-confirmed account deletion attempts (same keying as the sync write limiter).</summary>
    public static async ValueTask<object?> AccountDeletePerAccountFilter(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
        => await PerAccountAsync(context, next, static r => r.AccountDeletePerAccount);

    /// <summary>Per-account limit on password changes while signed in (same keying as the sync write limiter).</summary>
    public static async ValueTask<object?> PasswordChangePerAccountFilter(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
        => await PerAccountAsync(context, next, static r => r.PasswordChangePerAccount);

    private static async ValueTask<object?> PerAccountAsync(
        EndpointFilterInvocationContext context, EndpointFilterDelegate next, Func<AuthRateLimiters, BoundedRateLimiterCache> select)
    {
        var http = context.HttpContext;
        var options = http.RequestServices.GetRequiredService<PublicExposureHardeningOptions>();
        if (!options.Enabled)
        {
            return await next(context);
        }

        if (!Guid.TryParse(http.User.FindFirst("sub")?.Value, out var accountId) || accountId == Guid.Empty)
        {
            return ServiceUnavailable(); // authorization should have refused already; never an unkeyed bucket
        }

        var limiters = http.RequestServices.GetRequiredService<AuthRateLimiters>();
        if (!select(limiters).TryAcquire(accountId.ToString("N"), out var lease))
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
        => await PerEmailAsync(context, next, context.Arguments.OfType<LoginRequest>().FirstOrDefault()?.Email, static r => r.LoginPerEmail);

    /// <summary>Per-normalized-email forgot-password limit (same hashed key scheme as the login limiter).</summary>
    public static async ValueTask<object?> PasswordResetPerEmailFilter(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
        => await PerEmailAsync(context, next, context.Arguments.OfType<ForgotPasswordRequest>().FirstOrDefault()?.Email, static r => r.PasswordResetPerEmail);

    private static async ValueTask<object?> PerEmailAsync(
        EndpointFilterInvocationContext context, EndpointFilterDelegate next, string? email, Func<AuthRateLimiters, BoundedRateLimiterCache> select)
    {
        var http = context.HttpContext;
        var options = http.RequestServices.GetRequiredService<PublicExposureHardeningOptions>();
        if (!options.Enabled)
        {
            return await next(context);
        }

        // Invalid email syntax preserves the endpoint's own contract (the per-IP limits cover it);
        // we do not fabricate a limiter key from malformed input.
        if (email is null || !EmailAddressValidator.IsValid(email))
        {
            return await next(context);
        }

        var normalized = EmailNormalizer.Normalize(email);
        var key = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(normalized)));

        var limiters = http.RequestServices.GetRequiredService<AuthRateLimiters>();
        if (!select(limiters).TryAcquire(key, out var lease))
        {
            return ServiceUnavailable();
        }

        using (lease)
        {
            return lease.IsAcquired ? await next(context) : TooManyRequests(http, lease);
        }
    }

    /// <summary>
    /// Process-wide login budget (2D.2). Runs AFTER the per-IP and per-email limiters, so a request already
    /// rejected by those never consumes a global token. Rejection is the same generic 429. An unexpected
    /// limiter failure fails closed (503), never unrestricted login.
    /// </summary>
    public static async ValueTask<object?> GlobalLoginBudgetFilter(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        var http = context.HttpContext;
        var options = http.RequestServices.GetRequiredService<PublicExposureHardeningOptions>();
        if (!options.Enabled)
        {
            return await next(context);
        }

        var limiters = http.RequestServices.GetRequiredService<AuthRateLimiters>();
        RateLimitLease lease;
        try
        {
            lease = limiters.GlobalLoginBudget.AttemptAcquire(1); // QueueLimit = 0 → immediate, never queues
        }
        catch
        {
            return ServiceUnavailable(); // unexpected limiter failure → fail closed
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
