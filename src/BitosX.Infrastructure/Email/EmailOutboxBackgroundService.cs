using BitosX.Application.Email;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace BitosX.Infrastructure.Email;

/// <summary>
/// Hosted loop that periodically drains the email outbox and runs cleanup.
/// Runs in-process inside BitosX.Api (no separate worker). Cancellation-aware;
/// failures in one cycle are logged (without secrets) and do not stop the loop.
/// </summary>
public sealed class EmailOutboxBackgroundService : BackgroundService
{
    private readonly IEmailOutboxDispatcher _dispatcher;
    private readonly EmailOutboxOptions _options;
    private readonly ILogger<EmailOutboxBackgroundService> _logger;

    public EmailOutboxBackgroundService(
        IEmailOutboxDispatcher dispatcher, EmailOutboxOptions options, ILogger<EmailOutboxBackgroundService> logger)
    {
        _dispatcher = dispatcher;
        _options = options;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await _dispatcher.ProcessDueOnceAsync(stoppingToken).ConfigureAwait(false);
                await _dispatcher.RunCleanupOnceAsync(stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception)
            {
                _logger.LogWarning("Email outbox dispatch cycle failed; will retry next interval.");
            }

            try
            {
                await Task.Delay(_options.PollInterval, stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }
    }
}
