namespace BitosX.Application.Mfa;

public enum MfaAttemptAdmission
{
    Admitted,

    /// <summary>The account's second-step budget is used up; answer 429 with <see cref="MfaAttemptDecision.RetryAfter"/>.</summary>
    RateLimited,

    /// <summary>The limiter cannot track this account right now (capacity exhausted): fail closed with 503.</summary>
    Unavailable,
}

public sealed record MfaAttemptDecision(MfaAttemptAdmission Admission, TimeSpan? RetryAfter = null)
{
    public static MfaAttemptDecision Admitted { get; } = new(MfaAttemptAdmission.Admitted);
}

/// <summary>
/// Per-account bound on second sign-in step attempts, consulted once the challenge identifies the account and
/// before an attempt is reserved, so many challenges for one account (each needs the password) cannot multiply
/// the code guesses beyond the per-account budget. The HTTP host supplies the hardened implementation; without
/// it every attempt is admitted (the per-challenge attempt limit still applies).
/// </summary>
public interface IMfaAttemptLimiter
{
    MfaAttemptDecision TryAdmit(Guid accountId);
}

/// <summary>Admits every attempt (hardening disabled, or a host without HTTP limiters).</summary>
public sealed class UnlimitedMfaAttempts : IMfaAttemptLimiter
{
    public MfaAttemptDecision TryAdmit(Guid accountId) => MfaAttemptDecision.Admitted;
}
