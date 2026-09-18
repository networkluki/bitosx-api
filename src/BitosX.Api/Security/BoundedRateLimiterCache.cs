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
/// closed with 503). Existing partitions always keep their limiter, even at capacity. This makes
/// partition churn (flooding many distinct IPs/emails) unable to reset an exhausted limiter.</para>
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
    private readonly object _mutationLock = new();
    private readonly TokenBucketPolicyOptions _policy;
    private readonly int _maxPartitions;
    private readonly TimeSpan _idleExpiration;
    private readonly TimeProvider _clock;
    private readonly ITimer _sweepTimer;
    private volatile bool _disposed;

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
    /// Attempts to take one token from the partition's bucket.
    /// Returns false ONLY when the partition is new, the cache is at its maximum, and no entry is idle
    /// enough to reclaim — i.e. capacity exhaustion (the caller fails closed with 503). Returns true with
    /// a lease otherwise; <c>lease.IsAcquired</c> then carries the ordinary rate-limit decision. An
    /// existing partition always resolves (true), even when the cache is full. QueueLimit is 0 → never queues.
    /// </summary>
    public bool TryAcquire(string partitionKey, out RateLimitLease lease)
    {
        if (!TryGetOrAddEntry(partitionKey, out var entry))
        {
            lease = FailedLease.Instance; // capacity exhausted; caller must not treat this as a rate-limit lease
            return false;
        }

        Volatile.Write(ref entry.LastAccessTicks, _clock.GetUtcNow().UtcTicks);
        lease = entry.Limiter.AttemptAcquire(1);
        return true;
    }

    private bool TryGetOrAddEntry(string key, out Entry entry)
    {
        // Fast path: an existing partition ALWAYS resolves and is never evicted for capacity.
        if (_partitions.TryGetValue(key, out var found))
        {
            entry = found;
            return true;
        }

        lock (_mutationLock)
        {
            if (_partitions.TryGetValue(key, out found))
            {
                entry = found;
                return true;
            }

            if (_partitions.Count >= _maxPartitions)
            {
                // Reclaim ONLY idle-eligible entries; a live (non-idle) limiter is never sacrificed.
                ReclaimIdleLocked();
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
            _partitions[key] = created; // only ever added under the lock, after a capacity check → count never exceeds max
            entry = created;
            return true;
        }
    }

    /// <summary>Removes every entry that has been idle for at least the configured idle expiration.</summary>
    private void ReclaimIdleLocked()
    {
        var cutoff = _clock.GetUtcNow().UtcTicks - _idleExpiration.Ticks;
        foreach (var kv in _partitions)
        {
            if (Volatile.Read(ref kv.Value.LastAccessTicks) <= cutoff && _partitions.TryRemove(kv.Key, out var removed))
            {
                removed.Limiter.Dispose();
            }
        }
    }

    private void SweepIdle()
    {
        if (_disposed)
        {
            return;
        }

        // Removal-only; safe without the mutation lock (adds happen only under the lock).
        ReclaimIdleLocked();
    }

    public void Dispose()
    {
        _disposed = true;
        _sweepTimer.Dispose();
        foreach (var kv in _partitions)
        {
            kv.Value.Limiter.Dispose();
        }

        _partitions.Clear();
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
