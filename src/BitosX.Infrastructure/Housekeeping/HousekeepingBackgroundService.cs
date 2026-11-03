using BitosX.Application.Housekeeping;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace BitosX.Infrastructure.Housekeeping;

/// <summary>
/// Hosted loop that runs <see cref="HousekeepingRunner"/> one minute after startup and then every
/// <see cref="HousekeepingOptions.IntervalMinutes"/>. Cancellation-aware; a failed run is logged (error type only)
/// and does not stop the loop.
/// </summary>
public sealed class HousekeepingBackgroundService : BackgroundService
{
    private static readonly TimeSpan InitialDelay = TimeSpan.FromMinutes(1);

    private readonly HousekeepingRunner _runner;
    private readonly HousekeepingOptions _options;
    private readonly TimeProvider _clock;
    private readonly ILogger<HousekeepingBackgroundService> _logger;

    public HousekeepingBackgroundService(HousekeepingRunner runner, HousekeepingOptions options, TimeProvider clock, ILogger<HousekeepingBackgroundService> logger)
    {
        _runner = runner;
        _options = options;
        _clock = clock;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var delay = InitialDelay;
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(delay, _clock, stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }

            try
            {
                await _runner.RunOnceAsync(stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogWarning("Housekeeping run failed ({ErrorType}); will retry next interval.", ex.GetType().Name);
            }

            delay = _options.Interval;
        }
    }
}
