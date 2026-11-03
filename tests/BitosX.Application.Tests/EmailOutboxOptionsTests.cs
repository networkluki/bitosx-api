using BitosX.Application.Email;

namespace BitosX.Application.Tests;

public sealed class EmailOutboxOptionsTests
{
    [Fact]
    public void Defaults_AreValid() => new EmailOutboxOptions().Validate();

    [Theory]
    [InlineData(nameof(EmailOutboxOptions.MaxAttempts), 0)]
    [InlineData(nameof(EmailOutboxOptions.MaxAttempts), -1)]
    [InlineData(nameof(EmailOutboxOptions.MaxAttempts), 101)]
    [InlineData(nameof(EmailOutboxOptions.BatchSize), 0)]
    [InlineData(nameof(EmailOutboxOptions.BatchSize), 501)]
    public void OutOfRangeCounts_FailClosed(string property, int value)
    {
        var o = new EmailOutboxOptions();
        typeof(EmailOutboxOptions).GetProperty(property)!.SetValue(o, value);
        var ex = Assert.Throws<InvalidOperationException>(o.Validate);
        Assert.Contains("Email:Outbox:" + property, ex.Message);
    }

    [Theory]
    [InlineData(nameof(EmailOutboxOptions.PollInterval), "00:00:00")]
    [InlineData(nameof(EmailOutboxOptions.PollInterval), "-00:00:05")]
    [InlineData(nameof(EmailOutboxOptions.PollInterval), "02:00:00")]
    [InlineData(nameof(EmailOutboxOptions.LeaseDuration), "00:00:00")]
    [InlineData(nameof(EmailOutboxOptions.BackoffBase), "-00:00:01")]
    [InlineData(nameof(EmailOutboxOptions.RetentionPeriod), "00:10:00")]
    [InlineData(nameof(EmailOutboxOptions.RetentionPeriod), "400.00:00:00")]
    public void OutOfRangeDurations_FailClosed(string property, string value)
    {
        var o = new EmailOutboxOptions();
        typeof(EmailOutboxOptions).GetProperty(property)!.SetValue(o, TimeSpan.Parse(value, System.Globalization.CultureInfo.InvariantCulture));
        var ex = Assert.Throws<InvalidOperationException>(o.Validate);
        Assert.Contains("Email:Outbox:" + property, ex.Message);
    }
}
