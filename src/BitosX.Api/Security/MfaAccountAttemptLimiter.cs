using System.Threading.RateLimiting;
using BitosX.Application.Mfa;

namespace BitosX.Api.Security;

/// <summary>
/// The hardened <see cref="IMfaAttemptLimiter"/>: a per-account token bucket (<c>MfaPerAccount</c>) for the second
/// sign-in step, keyed by the account the challenge belongs to — a server-issued identity resolved from the
/// opaque challenge token, never client input. Inert unless public-exposure hardening is enabled, like every
/// other limiter. Capacity exhaustion fails closed (<see cref="MfaAttemptAdmission.Unavailable"/>, a 503).
/// </summary>
public sealed class MfaAccountAttemptLimiter : IMfaAttemptLimiter
{
    private readonly PublicExposureHardeningOptions _options;
    private readonly IServiceProvider _services;

    public MfaAccountAttemptLimiter(PublicExposureHardeningOptions options, IServiceProvider services)
    {
        _options = options;
        _services = services;
    }

    public MfaAttemptDecision TryAdmit(Guid accountId)
    {
        if (!_options.Enabled)
        {
            return MfaAttemptDecision.Admitted;
        }

        if (accountId == Guid.Empty)
        {
            return new MfaAttemptDecision(MfaAttemptAdmission.Unavailable); // never an unkeyed bucket
        }

        var limiters = _services.GetRequiredService<AuthRateLimiters>();
        if (!limiters.MfaPerAccount.TryAcquire(accountId.ToString("N"), out var lease))
        {
            return new MfaAttemptDecision(MfaAttemptAdmission.Unavailable);
        }

        using (lease)
        {
            if (lease.IsAcquired)
            {
                return MfaAttemptDecision.Admitted;
            }

            return new MfaAttemptDecision(
                MfaAttemptAdmission.RateLimited,
                lease.TryGetMetadata(MetadataName.RetryAfter, out var retryAfter) ? retryAfter : null);
        }
    }
}
