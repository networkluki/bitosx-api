using BitosX.Application.Email;

namespace BitosX.Application.Tests;

public sealed class EmailRetryBackoffTests
{
    private static EmailOutboxOptions Opts() => new() { BackoffBase = TimeSpan.FromSeconds(30) };

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(3)]
    [InlineData(5)]
    public void NextDelay_WithinEqualJitterBounds(int attempt)
    {
        var baseSeconds = 30.0 * Math.Pow(2, attempt);

        // rand=0 → lower bound (0.5×base); rand=1 → upper bound (1.0×base).
        var low = new DefaultEmailRetryBackoff(Opts(), () => 0.0).NextDelay(attempt).TotalSeconds;
        var high = new DefaultEmailRetryBackoff(Opts(), () => 1.0).NextDelay(attempt).TotalSeconds;

        Assert.Equal(baseSeconds * 0.5, low, precision: 3);
        Assert.Equal(baseSeconds * 1.0, high, precision: 3);
    }

    [Fact]
    public void NextDelay_IsJittered_NotConstant()
    {
        var opts = Opts();
        var a = new DefaultEmailRetryBackoff(opts, () => 0.2).NextDelay(2).TotalSeconds;
        var b = new DefaultEmailRetryBackoff(opts, () => 0.9).NextDelay(2).TotalSeconds;
        Assert.NotEqual(a, b, precision: 3);
        // Both remain within [0.5,1.0]×(30×4=120s) = [60,120].
        Assert.InRange(a, 60, 120);
        Assert.InRange(b, 60, 120);
    }

    [Fact]
    public void NextDelay_CapsExponentToAvoidOverflow()
    {
        // A huge attempt count must not overflow / throw.
        var d = new DefaultEmailRetryBackoff(Opts(), () => 1.0).NextDelay(1000);
        Assert.True(d > TimeSpan.Zero);
    }
}
