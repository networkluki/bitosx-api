namespace BitosX.Infrastructure.Security;

/// <summary>
/// Bounded-work admission settings for Argon2 password hashing (config section
/// <c>Security:PublicExposureHardening:Argon2</c>). This bound is a resource-safety property of password
/// hashing itself, so it is ALWAYS active — independent of <c>PublicExposureHardening:Enabled</c> — and is
/// validated fail-closed at startup. It caps how many Argon2 operations may execute concurrently and how
/// many may wait, and how long a waiter may wait, so unauthenticated login load cannot build an unbounded
/// backlog on the 1-vCPU host.
/// </summary>
public sealed class Argon2AdmissionOptions
{
    public const string SectionName = "Security:PublicExposureHardening:Argon2";

    /// <summary>Maximum Argon2 operations executing simultaneously.</summary>
    public int MaxConcurrent { get; set; } = 2;

    /// <summary>Maximum operations allowed to wait for an execution slot (bounded queue).</summary>
    public int QueueCapacity { get; set; } = 4;

    /// <summary>Maximum time a queued operation waits for capacity before it is rejected as overloaded.</summary>
    public int AcquireTimeoutMilliseconds { get; set; } = 2000;

    public void Validate()
    {
        if (MaxConcurrent <= 0) throw new InvalidOperationException($"{SectionName}:MaxConcurrent must be greater than zero.");
        if (QueueCapacity < 0) throw new InvalidOperationException($"{SectionName}:QueueCapacity must not be negative.");
        if (AcquireTimeoutMilliseconds <= 0) throw new InvalidOperationException($"{SectionName}:AcquireTimeoutMilliseconds must be greater than zero.");
    }
}
