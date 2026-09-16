namespace BitosX.Application.Email;

/// <summary>Non-secret outbox dispatcher settings.</summary>
public sealed class EmailOutboxOptions
{
    public int MaxAttempts { get; set; } = 6;
    public int BatchSize { get; set; } = 20;
    public TimeSpan PollInterval { get; set; } = TimeSpan.FromSeconds(15);
    public TimeSpan LeaseDuration { get; set; } = TimeSpan.FromMinutes(2);
    public TimeSpan BackoffBase { get; set; } = TimeSpan.FromSeconds(30);
    public TimeSpan RetentionPeriod { get; set; } = TimeSpan.FromDays(7);
}
