using System.Collections.Concurrent;
using System.Threading.RateLimiting;

namespace BitosX.Api.Security;

/// <summary>
/// A process-local, memory-bounded cache of per-partition <see cref="TokenBucketRateLimiter"/> instances
/// (one per client-IP or per-email-hash key).
///
/// <para><b>Security invariant:</b> <see cref="_maxPartitions"/> is a memory-safety boundary, NOT a
/// licence to reset live rate-limit state. A limiter that still holds rate-limit state is NEVER evicted
/// merely because unrelated partition keys arrive. An entry may be reclaimed only when it carries no state:
/// it has been idle for at least <see cref="_idleExpiration"/>, OR its bucket has refilled to full capacity
/// (a full bucket is indistinguishable from a brand-new one, so dropping it resets nothing). When a NEW key
/// arrives and the cache is full, only such entries are reclaimed; if none are eligible the new key is
/// refused (<see cref="TryAcquire"/> returns false → the caller fails closed with 503). Existing partitions
/// always keep their limiter, even at capacity. Reclaiming full buckets means an attacker who wants to keep
/// the cache full must keep every one of its partitions drained (re-touch each within one refill period,
/// seconds to a few minutes), not merely touch it once per idle window (30 minutes by default).</para>
///
/// <para><b>Lifetime invariant:</b> acquisition and removal/disposal are serialized under a single lock,
/// so a limiter can never be disposed while an acquisition against it is in progress (no use-after-dispose,
/// no <see cref="ObjectDisposedException"/>, and an in-use partition is never reclaimed underneath a
/// caller). The clock is read BEFORE the lock is taken and never inside it: a <see cref="TimeProvider"/> may
/// run due timer callbacks (the idle sweep) inline on the calling thread, and a sweep re-entering the lock
/// from inside an acquisition would dispose the very limiter being acquired. The sweep additionally refuses to
/// run re-entrantly. The token-bucket acquire is an O(1) in-memory operation, so the lock is held only briefly.</para>
///
/// Rate limiting here is single-instance/process-local; a multi-instance deployment needs a separately
/// designed distributed limiter. The raw partition value is never stored or logged beyond the caller's key.
/// </summary>
public sealed class BoundedRateLimiterCache : IDisposable
{
    private sealed class Entry
    {
        public required TokenBucketRateLimiter Limiter { get; init; }
        public long LastAccessTicks;
    }

    private readonly ConcurrentDictionary<string, Entry> _partitions = new(StringComparer.Ordinal);
    private readonly object _gate = new();
    private readonly TokenBucketPolicyOptions _policy;
    private readonly int _maxPartitions;
    private readonly TimeSpan _idleExpiration;
    private readonly TimeProvider _clock;
    private readonly ITimer _sweepTimer;
    private bool _disposed;

    public BoundedRateLimiterCache(TokenBucketPolicyOptions policy, int maxPartitions, TimeSpan idleExpiration, TimeProvider clock)
    {
        _policy = policy;
        _maxPartitions = maxPartitions;
        _idleExpiration = idleExpiration;
        _clock = clock;
        var interval = TimeSpan.FromSeconds(Math.Clamp(idleExpiration.TotalSeconds / 2, 30, 300));
        _sweepTimer = clock.CreateTimer(_ => SweepIdle(), null, interval, interval);
    }

    /// <summary>Current tracked partition count (for tests / diagnostics — never the keys themselves).</summary>
    public int PartitionCount => _partitions.Count;

    /// <summary>
    /// Attempts to take one token from the partition's bucket. Acquisition, creation, and idle reclamation
    /// all run under one lock, so the returned limiter cannot be disposed concurrently. Returns false ONLY
    /// when the partition is new, the cache is at its maximum, and no entry is idle enough to reclaim —
    /// i.e. capacity exhaustion (the caller fails closed with 503). Otherwise returns true with a lease
    /// whose <c>IsAcquired</c> carries the ordinary rate-limit decision. QueueLimit is 0 → never queues.
    /// </summary>
    public bool TryAcquire(string partitionKey, out RateLimitLease lease)
    {
        // Read the clock OUTSIDE the lock (see the lifetime invariant).
        var nowTicks = _clock.GetUtcNow().UtcTicks;
        lock (_gate)
        {
            if (_disposed || !TryResolveEntryLocked(partitionKey, nowTicks, out var entry))
            {
                lease = FailedLease.Instance; // capacity exhausted (or shutting down); not a rate-limit lease
                return false;
            }

            entry.LastAccessTicks = nowTicks;
            lease = entry.Limiter.AttemptAcquire(1); // safe: no concurrent Dispose can run under the same lock
            return true;
        }
    }

    private bool TryResolveEntryLocked(string key, long nowTicks, out Entry entry)
    {
        if (_partitions.TryGetValue(key, out var found))
        {
            entry = found; // existing partition ALWAYS resolves and is never evicted for capacity
            return true;
        }

        if (_partitions.Count >= _maxPartitions)
        {
            ReclaimStatelessLocked(nowTicks); // reclaim ONLY entries that carry no state; a live limiter is never sacrificed
            if (_partitions.Count >= _maxPartitions)
            {
                entry = null!;
                return false; // full and nothing idle → refuse the new key (fail closed)
            }
        }

        var created = new Entry
        {
            Limiter = new TokenBucketRateLimiter(new TokenBucketRateLimiterOptions
            {
                TokenLimit = _policy.TokenLimit,
                TokensPerPeriod = _policy.TokensPerPeriod,
                ReplenishmentPeriod = TimeSpan.FromSeconds(_policy.ReplenishmentSeconds),
                AutoReplenishment = true,
                QueueLimit = 0,
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
            }),
            LastAccessTicks = nowTicks,
        };
        _partitions[key] = created; // only added under the lock after a capacity check → count never exceeds max
        entry = created;
        return true;
    }

    /// <summary>
    /// Removes + disposes every entry that carries no rate-limit state: idle for at least the configured idle
    /// expiration, or with a bucket back at full capacity. Caller holds the lock.
    /// </summary>
    private void ReclaimStatelessLocked(long nowTicks)
    {
        var cutoff = nowTicks - _idleExpiration.Ticks;
        foreach (var kv in _partitions)
        {
            if ((kv.Value.LastAccessTicks <= cutoff || IsFull(kv.Value.Limiter)) && _partitions.TryRemove(kv.Key, out var removed))
            {
                removed.Limiter.Dispose(); // safe: acquisition for the same cache cannot run concurrently
            }
        }
    }

    private bool IsFull(TokenBucketRateLimiter limiter)
        => limiter.GetStatistics() is { } statistics && statistics.CurrentAvailablePermits >= _policy.TokenLimit;

    private void SweepIdle()
    {
        // Never re-entrantly: a TimeProvider may run this callback inline on a thread that already holds the
        // lock (inside TryAcquire); reclaiming there could dispose the limiter that thread is acquiring.
        if (Monitor.IsEntered(_gate))
        {
            return;
        }

        var nowTicks = _clock.GetUtcNow().UtcTicks; // outside the lock, like TryAcquire
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            ReclaimStatelessLocked(nowTicks);
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            _sweepTimer.Dispose();
            foreach (var kv in _partitions)
            {
                kv.Value.Limiter.Dispose();
            }

            _partitions.Clear();
        }
    }

    /// <summary>A never-acquired lease returned when capacity is exhausted (distinct from a rate-limit rejection).</summary>
    private sealed class FailedLease : RateLimitLease
    {
        public static readonly FailedLease Instance = new();
        public override bool IsAcquired => false;
        public override IEnumerable<string> MetadataNames => [];
        public override bool TryGetMetadata(string metadataName, out object? metadata) { metadata = null; return false; }
    }
}
