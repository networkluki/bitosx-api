using System.Collections.Concurrent;
using System.Threading.RateLimiting;

namespace BitosX.Api.Security;

/// <summary>
/// A process-local, memory-bounded cache of per-partition <see cref="TokenBucketRateLimiter"/> instances
/// (one per client-IP or per-email-hash key).
///
/// <para><b>Security invariant:</b> <see cref="_maxPartitions"/> is a memory-safety boundary, NOT a
/// licence to reset live rate-limit state. A limiter that has not been idle for at least
/// <see cref="_idleExpiration"/> is NEVER evicted merely because unrelated partition keys arrive. When a
/// NEW key arrives and the cache is full, only entries already past the idle threshold may be reclaimed;
/// if none are eligible the new key is refused (<see cref="TryAcquire"/> returns false → the caller fails
/// closed with 503). Existing partitions always keep their limiter, even at capacity.</para>
///
/// <para><b>Lifetime invariant:</b> acquisition and removal/disposal are serialized under a single lock,
/// so a limiter can never be disposed while an acquisition against it is in progress (no use-after-dispose,
/// no <see cref="ObjectDisposedException"/>, and an in-use partition is never reclaimed underneath a
/// caller). The token-bucket acquire is an O(1) in-memory operation, so the lock is held only briefly.</para>
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
        lock (_gate)
        {
            if (_disposed || !TryResolveEntryLocked(partitionKey, out var entry))
            {
                lease = FailedLease.Instance; // capacity exhausted (or shutting down); not a rate-limit lease
                return false;
            }

            entry.LastAccessTicks = _clock.GetUtcNow().UtcTicks;
            lease = entry.Limiter.AttemptAcquire(1); // safe: no concurrent Dispose can run under the same lock
            return true;
        }
    }

    private bool TryResolveEntryLocked(string key, out Entry entry)
    {
        if (_partitions.TryGetValue(key, out var found))
        {
            entry = found; // existing partition ALWAYS resolves and is never evicted for capacity
            return true;
        }

        if (_partitions.Count >= _maxPartitions)
        {
            ReclaimIdleLocked(); // reclaim ONLY idle-eligible entries; a live limiter is never sacrificed
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
            LastAccessTicks = _clock.GetUtcNow().UtcTicks,
        };
        _partitions[key] = created; // only added under the lock after a capacity check → count never exceeds max
        entry = created;
        return true;
    }

    /// <summary>Removes + disposes every entry idle for at least the configured idle expiration. Caller holds the lock.</summary>
    private void ReclaimIdleLocked()
    {
        var cutoff = _clock.GetUtcNow().UtcTicks - _idleExpiration.Ticks;
        foreach (var kv in _partitions)
        {
            if (kv.Value.LastAccessTicks <= cutoff && _partitions.TryRemove(kv.Key, out var removed))
            {
                removed.Limiter.Dispose(); // safe: acquisition for the same cache cannot run concurrently
            }
        }
    }

    private void SweepIdle()
    {
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            ReclaimIdleLocked();
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
