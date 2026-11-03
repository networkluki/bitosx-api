using System.Threading.RateLimiting;
using BitosX.Application.Security;

namespace BitosX.Infrastructure.Security;

/// <summary>
/// Bounded admission gate for Argon2 work, shared process-wide by every production Argon2 operation
/// (login, verify-email, password reset, password change, account deletion and TOTP management all go through the same hasher, so no
/// unbounded alternate path can appear). Built on <see cref="ConcurrencyLimiter"/> (a BCL primitive):
///
/// <list type="bullet">
/// <item>at most <c>MaxConcurrent</c> operations execute simultaneously (PermitLimit);</item>
/// <item>at most <c>QueueCapacity</c> additional operations wait (QueueLimit) — a further operation is
///   rejected immediately;</item>
/// <item>waiters are admitted <b>oldest-first / FIFO</b> (<see cref="QueueProcessingOrder.OldestFirst"/>);</item>
/// <item>a waiter waits at most <c>AcquireTimeoutMilliseconds</c>, then is rejected as overloaded;</item>
/// <item>cancellation removes the waiter promptly and never consumes/leaks a permit;</item>
/// <item>the lease is disposed exactly once (via <c>using</c>) on success, failure, or exception,
///   releasing its permit.</item>
/// </list>
///
/// Capacity exhaustion (queue full) and acquire timeout both surface as
/// <see cref="PasswordHashingCapacityExceededException"/>; genuine request cancellation propagates as
/// <see cref="OperationCanceledException"/> and is never rewritten as overload.
/// </summary>
public sealed class Argon2WorkGate : IDisposable
{
    private readonly ConcurrencyLimiter _limiter;
    private readonly TimeSpan _acquireTimeout;

    public Argon2WorkGate(Argon2AdmissionOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        _acquireTimeout = TimeSpan.FromMilliseconds(options.AcquireTimeoutMilliseconds);
        _limiter = new ConcurrencyLimiter(new ConcurrencyLimiterOptions
        {
            PermitLimit = options.MaxConcurrent,
            QueueLimit = options.QueueCapacity,
            QueueProcessingOrder = QueueProcessingOrder.OldestFirst, // FIFO
        });
    }

    /// <summary>
    /// Acquires one execution permit. The returned lease must be disposed to release the permit. Throws
    /// <see cref="PasswordHashingCapacityExceededException"/> when the queue is full or the wait times out;
    /// rethrows <see cref="OperationCanceledException"/> for genuine caller cancellation.
    /// </summary>
    public async ValueTask<RateLimitLease> AcquireAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCts.CancelAfter(_acquireTimeout);

        RateLimitLease lease;
        try
        {
            lease = await _limiter.AcquireAsync(1, timeoutCts.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (timeoutCts.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
        {
            // Timed out waiting for capacity → overload, not cancellation.
            throw new PasswordHashingCapacityExceededException();
        }

        if (!lease.IsAcquired)
        {
            lease.Dispose(); // queue full → immediate overload
            throw new PasswordHashingCapacityExceededException();
        }

        return lease;
    }

    public void Dispose() => _limiter.Dispose();
}
