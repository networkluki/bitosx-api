namespace BitosX.Application.Email;

/// <summary>Computes the delay before the next outbox delivery attempt.</summary>
public interface IEmailRetryBackoff
{
    TimeSpan NextDelay(int attemptCount);
}

/// <summary>
/// Bounded exponential backoff with "equal jitter": for attempt n the base is
/// <c>BackoffBase × 2^n</c> (n capped to avoid overflow), and the actual delay is
/// <c>base × (0.5 + 0.5 × rand)</c> — i.e. uniformly in <c>[0.5×base, 1.0×base]</c>.
/// Jitter spreads retries without exceeding the exponential upper bound (so the
/// retry schedule stays inside the token TTL). The random source is injectable
/// for deterministic tests.
/// </summary>
public sealed class DefaultEmailRetryBackoff : IEmailRetryBackoff
{
    private const int MaxExponent = 20; // caps 2^n to avoid overflow
    private readonly TimeSpan _base;
    private readonly Func<double> _random;

    public DefaultEmailRetryBackoff(EmailOutboxOptions options, Func<double>? random = null)
    {
        _base = options.BackoffBase;
        _random = random ?? Random.Shared.NextDouble;
    }

    public TimeSpan NextDelay(int attemptCount)
    {
        var exponent = Math.Clamp(attemptCount, 0, MaxExponent);
        var baseSeconds = _base.TotalSeconds * Math.Pow(2, exponent);
        var jittered = baseSeconds * (0.5 + 0.5 * Math.Clamp(_random(), 0.0, 1.0));
        return TimeSpan.FromSeconds(jittered);
    }
}
