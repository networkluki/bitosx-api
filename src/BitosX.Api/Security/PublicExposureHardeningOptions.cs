namespace BitosX.Api.Security;

/// <summary>
/// A single validated configuration model for Phase 2D public-exposure hardening
/// (<c>Security:PublicExposureHardening</c>). Rate-limit literals live here, never scattered in
/// endpoint code. When <see cref="Enabled"/> is false (the development default) the auth rate
/// limiters are inert; production with the Login capability must enable it before public deployment.
/// Values are validated fail-closed at startup (<see cref="Validate"/>); nothing is silently clamped.
/// </summary>
public sealed class PublicExposureHardeningOptions
{
    public const string SectionName = "Security:PublicExposureHardening";

    public bool Enabled { get; set; }

    public TokenBucketPolicyOptions LoginPerIp { get; set; } = new() { TokenLimit = 10, TokensPerPeriod = 5, ReplenishmentSeconds = 30 };

    public TokenBucketPolicyOptions LoginPerEmail { get; set; } = new() { TokenLimit = 5, TokensPerPeriod = 1, ReplenishmentSeconds = 180 };

    public TokenBucketPolicyOptions RefreshPerIp { get; set; } = new() { TokenLimit = 30, TokensPerPeriod = 15, ReplenishmentSeconds = 30 };

    public PartitionStateOptions PartitionState { get; set; } = new();

    /// <summary>Process-wide login admission budget (2D.2). Gated by <see cref="Enabled"/>.</summary>
    public TokenBucketPolicyOptions GlobalLoginBudget { get; set; } = new() { TokenLimit = 30, TokensPerPeriod = 15, ReplenishmentSeconds = 15 };

    /// <summary>Bounded login-response jitter (2D.2). Gated by <see cref="Enabled"/>.</summary>
    public LoginJitterOptions LoginJitter { get; set; } = new();

    /// <summary>Fail-closed validation of every security-relevant value. Throws on any invalid/out-of-range value.</summary>
    public void Validate()
    {
        LoginPerIp.Validate($"{SectionName}:LoginPerIp");
        LoginPerEmail.Validate($"{SectionName}:LoginPerEmail");
        RefreshPerIp.Validate($"{SectionName}:RefreshPerIp");
        PartitionState.Validate($"{SectionName}:PartitionState");
        GlobalLoginBudget.Validate($"{SectionName}:GlobalLoginBudget");
        LoginJitter.Validate($"{SectionName}:LoginJitter");
    }
}

/// <summary>Bounded login-response jitter range (inclusive), in milliseconds.</summary>
public sealed class LoginJitterOptions
{
    public int MinMilliseconds { get; set; } = 25;
    public int MaxMilliseconds { get; set; } = 75;

    public void Validate(string key)
    {
        if (MinMilliseconds < 0) throw new InvalidOperationException($"{key}:MinMilliseconds must not be negative.");
        if (MaxMilliseconds < MinMilliseconds) throw new InvalidOperationException($"{key}:MaxMilliseconds must be greater than or equal to MinMilliseconds.");
    }
}

/// <summary>Token-bucket policy (fixed <c>QueueLimit = 0</c> for HTTP auth limiters — never configurable here).</summary>
public sealed class TokenBucketPolicyOptions
{
    public int TokenLimit { get; set; }
    public int TokensPerPeriod { get; set; }
    public int ReplenishmentSeconds { get; set; }

    public void Validate(string key)
    {
        if (TokenLimit <= 0) throw new InvalidOperationException($"{key}:TokenLimit must be greater than zero.");
        if (TokensPerPeriod <= 0) throw new InvalidOperationException($"{key}:TokensPerPeriod must be greater than zero.");
        if (TokensPerPeriod > TokenLimit) throw new InvalidOperationException($"{key}:TokensPerPeriod must not exceed TokenLimit.");
        if (ReplenishmentSeconds <= 0) throw new InvalidOperationException($"{key}:ReplenishmentSeconds must be greater than zero.");
    }
}

/// <summary>Bounds for in-process rate-limiter partition state (memory safety under hostile unique keys).</summary>
public sealed class PartitionStateOptions
{
    public int MaxIpPartitions { get; set; } = 4096;
    public int MaxEmailPartitions { get; set; } = 4096;
    public int IdleExpirationMinutes { get; set; } = 30;

    public void Validate(string key)
    {
        if (MaxIpPartitions <= 0) throw new InvalidOperationException($"{key}:MaxIpPartitions must be greater than zero.");
        if (MaxEmailPartitions <= 0) throw new InvalidOperationException($"{key}:MaxEmailPartitions must be greater than zero.");
        if (IdleExpirationMinutes <= 0) throw new InvalidOperationException($"{key}:IdleExpirationMinutes must be greater than zero.");
    }
}
