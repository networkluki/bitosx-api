namespace BitosX.Api.Security;

/// <summary>
/// Applies bounded, uniformly-random login-response jitter (defense-in-depth against fine-grained timing
/// analysis of the login path). Inert unless <see cref="PublicExposureHardeningOptions.Enabled"/> is true.
/// The delay is NOT derived from any identity data (email/account/password/IP) — it is a fresh uniform
/// draw per response. Jitter is a supplement, never a replacement for constant-time credential handling,
/// Argon2 work, or rate limiting.
/// </summary>
public interface ILoginResponseJitter
{
    /// <summary>Awaits a random delay in the configured inclusive range (no-op when hardening is disabled).</summary>
    Task ApplyAsync(CancellationToken cancellationToken);
}

/// <inheritdoc />
public sealed class LoginResponseJitter : ILoginResponseJitter
{
    private readonly PublicExposureHardeningOptions _options;
    private readonly TimeProvider _clock;

    public LoginResponseJitter(PublicExposureHardeningOptions options, TimeProvider clock)
    {
        _options = options;
        _clock = clock;
    }

    public async Task ApplyAsync(CancellationToken cancellationToken)
    {
        if (!_options.Enabled)
        {
            return;
        }

        var min = _options.LoginJitter.MinMilliseconds;
        var max = _options.LoginJitter.MaxMilliseconds;
        var milliseconds = min == max ? min : Random.Shared.Next(min, max + 1); // inclusive upper bound
        if (milliseconds <= 0)
        {
            return;
        }

        await Task.Delay(TimeSpan.FromMilliseconds(milliseconds), _clock, cancellationToken).ConfigureAwait(false);
    }
}
