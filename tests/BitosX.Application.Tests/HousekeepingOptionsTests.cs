using BitosX.Application.Housekeeping;

namespace BitosX.Application.Tests;

public sealed class HousekeepingOptionsTests
{
    [Fact]
    public void Defaults_AreValid_AndSensible()
    {
        var o = new HousekeepingOptions();
        o.Validate();
        Assert.True(o.Enabled);
        Assert.Equal(TimeSpan.FromDays(30), o.Retention);
        Assert.Equal(TimeSpan.FromHours(1), o.Interval);
    }

    [Theory]
    [InlineData(0, 30, 200, 50)]
    [InlineData(1441, 30, 200, 50)]
    [InlineData(60, 0, 200, 50)]
    [InlineData(60, 3651, 200, 50)]
    [InlineData(60, 30, 0, 50)]
    [InlineData(60, 30, 5001, 50)]
    [InlineData(60, 30, 200, 0)]
    [InlineData(60, 30, 200, 1001)]
    public void OutOfRange_FailsClosed(int interval, int retention, int batch, int maxBatches)
        => Assert.Throws<InvalidOperationException>(() => new HousekeepingOptions
        {
            IntervalMinutes = interval, RetentionDays = retention, BatchSize = batch, MaxBatchesPerRun = maxBatches,
        }.Validate());
}
