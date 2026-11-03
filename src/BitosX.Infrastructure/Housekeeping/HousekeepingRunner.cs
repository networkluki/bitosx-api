using BitosX.Application.Abstractions.Persistence;
using BitosX.Application.Housekeeping;
using BitosX.Application.Security;
using Microsoft.Extensions.Logging;

namespace BitosX.Infrastructure.Housekeeping;

/// <summary>Counts deleted by one housekeeping run.</summary>
public sealed record HousekeepingResult(int EmailChallenges, int MfaChallenges, int Sessions);

/// <summary>
/// One housekeeping pass: for each kind of dead row, delete batches through the store until a batch comes back
/// short or <see cref="HousekeepingOptions.MaxBatchesPerRun"/> is reached. The cutoff is now minus the retention
/// window; a session counts as idle-expired once its idle lifetime ended before that cutoff. Logs counts only.
/// </summary>
public sealed class HousekeepingRunner
{
    private readonly IHousekeepingStore _store;
    private readonly HousekeepingOptions _options;
    private readonly TimeSpan _idleLifetime;
    private readonly TimeProvider _clock;
    private readonly ILogger<HousekeepingRunner> _logger;

    public HousekeepingRunner(IHousekeepingStore store, HousekeepingOptions options, RefreshTokenOptions sessions, TimeProvider clock, ILogger<HousekeepingRunner> logger)
    {
        _store = store;
        _options = options;
        _idleLifetime = sessions.IdleLifetime;
        _clock = clock;
        _logger = logger;
    }

    public async Task<HousekeepingResult> RunOnceAsync(CancellationToken cancellationToken = default)
    {
        var cutoff = _clock.GetUtcNow().UtcDateTime - _options.Retention;
        var idleCutoff = cutoff - _idleLifetime;

        var email = await DrainAsync(batch => _store.DeleteExpiredEmailChallengesAsync(cutoff, batch, cancellationToken), cancellationToken).ConfigureAwait(false);
        var mfa = await DrainAsync(batch => _store.DeleteExpiredMfaChallengesAsync(cutoff, batch, cancellationToken), cancellationToken).ConfigureAwait(false);
        var sessions = await DrainAsync(batch => _store.DeleteDeadSessionsAsync(cutoff, idleCutoff, batch, cancellationToken), cancellationToken).ConfigureAwait(false);

        var result = new HousekeepingResult(email, mfa, sessions);
        if (email + mfa + sessions > 0)
        {
            _logger.LogInformation(
                "Housekeeping deleted {EmailChallenges} email challenges, {MfaChallenges} MFA challenges and {Sessions} sessions (with their refresh tokens).",
                email, mfa, sessions);
        }

        return result;
    }

    private async Task<int> DrainAsync(Func<int, Task<int>> deleteBatch, CancellationToken cancellationToken)
    {
        var total = 0;
        for (var i = 0; i < _options.MaxBatchesPerRun; i++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var deleted = await deleteBatch(_options.BatchSize).ConfigureAwait(false);
            total += deleted;
            if (deleted < _options.BatchSize)
            {
                break;
            }
        }

        return total;
    }
}
