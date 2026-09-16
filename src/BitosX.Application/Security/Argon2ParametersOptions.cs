namespace BitosX.Application.Security;

/// <summary>
/// Argon2id parameters + verification resource ceilings. Active hashing memory
/// is bounded by a hard service budget: <c>MemoryKiB × MaxConcurrency ≤ 192 MiB</c>.
/// Verification ceilings are derived from the same budget so a hostile stored
/// hash can never demand more CPU/memory than the service is configured to spend.
/// Final values are locked by the on-box benchmark (see SECURITY_MODEL.md).
/// </summary>
public sealed class Argon2ParametersOptions
{
    /// <summary>Hard service-wide Argon2 memory budget in KiB (192 MiB).</summary>
    public const int MemoryBudgetKiB = 192 * 1024;

    /// <summary>Absolute floor for accepted memory (8 MiB).</summary>
    public const int AbsoluteMinMemoryKiB = 8 * 1024;

    // Benchmark-locked on bitosx-prod (1 vCPU / ~1 GiB): see SECURITY_MODEL.md.
    public int MemoryKiB { get; set; } = 19456; // 19 MiB
    public int Iterations { get; set; } = 3;
    public int Lanes { get; set; } = 1;          // p = 1 fixed for 1 vCPU
    public int MaxConcurrency { get; set; } = 1; // cap=1: lowest memory + predictable latency

    /// <summary>Override for the max memory (KiB) accepted at verification; null = budget-derived.</summary>
    public int? MaxVerifyMemoryKiB { get; set; }

    /// <summary>Override for the max iterations accepted at verification; null = 2× active.</summary>
    public int? MaxVerifyIterations { get; set; }

    /// <summary>
    /// Max memory (KiB) accepted when verifying a stored hash: never exceeds the
    /// per-slot budget (<c>192 MiB / MaxConcurrency</c>) and never below the active
    /// hashing memory (so current hashes always verify).
    /// </summary>
    public int EffectiveMaxVerifyMemoryKiB()
    {
        var concurrency = Math.Max(1, MaxConcurrency);
        var perSlotBudget = MemoryBudgetKiB / concurrency;
        var ceiling = MaxVerifyMemoryKiB ?? perSlotBudget;
        ceiling = Math.Min(ceiling, perSlotBudget); // clamp to budget
        return Math.Max(ceiling, MemoryKiB);        // but always accept active params
    }

    /// <summary>Max iterations accepted when verifying: default 2× active, never below active.</summary>
    public int EffectiveMaxVerifyIterations()
        => Math.Max(MaxVerifyIterations ?? (Iterations * 2), Iterations);
}
