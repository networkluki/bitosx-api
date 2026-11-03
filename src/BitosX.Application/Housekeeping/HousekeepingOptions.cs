namespace BitosX.Application.Housekeeping;

/// <summary>
/// Retention of dead authentication state (<c>Housekeeping</c>): expired/consumed email challenges (with their
/// outbox rows), spent/expired MFA challenges, and revoked/expired sessions with their refresh tokens are
/// deleted once they have been dead for <see cref="RetentionDays"/>. Deletes run in small batches over indexes.
/// Validated fail-closed at startup.
/// </summary>
public sealed class HousekeepingOptions
{
    public const string SectionName = "Housekeeping";

    /// <summary>Run the background service (default on). Off only for a host that prunes some other way.</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>Minutes between runs (1..1440). The first run starts one minute after startup.</summary>
    public int IntervalMinutes { get; set; } = 60;

    /// <summary>How long dead rows are kept before they are deleted, in days (1..3650).</summary>
    public int RetentionDays { get; set; } = 30;

    /// <summary>Rows per DELETE statement (1..5000): short statements, small lock sets.</summary>
    public int BatchSize { get; set; } = 200;

    /// <summary>Upper bound on batches per table per run (1..1000), so one run never runs unbounded.</summary>
    public int MaxBatchesPerRun { get; set; } = 50;

    public TimeSpan Interval => TimeSpan.FromMinutes(IntervalMinutes);

    public TimeSpan Retention => TimeSpan.FromDays(RetentionDays);

    public void Validate()
    {
        if (IntervalMinutes is < 1 or > 1440) throw new InvalidOperationException($"{SectionName}:IntervalMinutes must be between 1 and 1440.");
        if (RetentionDays is < 1 or > 3650) throw new InvalidOperationException($"{SectionName}:RetentionDays must be between 1 and 3650.");
        if (BatchSize is < 1 or > 5000) throw new InvalidOperationException($"{SectionName}:BatchSize must be between 1 and 5000.");
        if (MaxBatchesPerRun is < 1 or > 1000) throw new InvalidOperationException($"{SectionName}:MaxBatchesPerRun must be between 1 and 1000.");
    }
}
