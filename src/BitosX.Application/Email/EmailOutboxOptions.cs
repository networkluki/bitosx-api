namespace BitosX.Application.Email;

/// <summary>Non-secret outbox dispatcher settings (<c>Email:Outbox</c>). Validated fail-closed at startup.</summary>
public sealed class EmailOutboxOptions
{
    public const string SectionName = "Email:Outbox";

    public int MaxAttempts { get; set; } = 6;
    public int BatchSize { get; set; } = 20;
    public TimeSpan PollInterval { get; set; } = TimeSpan.FromSeconds(15);

    /// <summary>The lease taken (and renewed) for ONE row right before its send; it must outlive one SMTP attempt.</summary>
    public TimeSpan LeaseDuration { get; set; } = TimeSpan.FromMinutes(2);

    public TimeSpan BackoffBase { get; set; } = TimeSpan.FromSeconds(30);
    public TimeSpan RetentionPeriod { get; set; } = TimeSpan.FromDays(7);

    /// <summary>
    /// Fail-closed bounds: a zero or negative value would spin the loop against the database, never retry, or
    /// make <c>LIMIT</c> meaningless. Throws <see cref="InvalidOperationException"/> naming the key.
    /// </summary>
    public void Validate()
    {
        if (MaxAttempts is < 1 or > 100) throw new InvalidOperationException($"{SectionName}:MaxAttempts must be between 1 and 100.");
        if (BatchSize is < 1 or > 500) throw new InvalidOperationException($"{SectionName}:BatchSize must be between 1 and 500.");
        if (PollInterval < TimeSpan.FromSeconds(1) || PollInterval > TimeSpan.FromHours(1)) throw new InvalidOperationException($"{SectionName}:PollInterval must be between 00:00:01 and 01:00:00.");
        if (LeaseDuration <= TimeSpan.Zero || LeaseDuration > TimeSpan.FromHours(1)) throw new InvalidOperationException($"{SectionName}:LeaseDuration must be positive and at most 01:00:00.");
        if (BackoffBase <= TimeSpan.Zero || BackoffBase > TimeSpan.FromHours(1)) throw new InvalidOperationException($"{SectionName}:BackoffBase must be positive and at most 01:00:00.");
        if (RetentionPeriod < TimeSpan.FromHours(1) || RetentionPeriod > TimeSpan.FromDays(365)) throw new InvalidOperationException($"{SectionName}:RetentionPeriod must be between 01:00:00 and 365.00:00:00.");
    }
}
