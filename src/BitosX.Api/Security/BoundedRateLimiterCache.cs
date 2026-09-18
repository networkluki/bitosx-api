using System.Collections.Concurrent;
using System.Threading.RateLimiting;

namespace BitosX.Api.Security;

/// <summary>
/// A process-local, memory-bounded cache of per-partition <see cref="TokenBucketRateLimiter"/> instances
/// (one per client-IP or per-email-hash key). Enforces a hard maximum partition count with LRU eviction
/// and periodic idle expiration so a flood of unique keys cannot grow application memory without bound.
/// Rate limiting here is single-instance/process-local; a multi-instance deployment needs a separately
/// designed distributed limiter. Never stores or logs the raw partition value beyond the caller's key.
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

    /// <summary>Attempts to take one token from the partition's bucket. QueueLimit is 0, so it never queues.</summary>
    public RateLimitLease AttemptAcquire(string partitionKey)
    {
        var entry = GetOrAddEntry(partitionKey);
        Volatile.Write(ref entry.LastAccessTicks, _clock.GetUtcNow().UtcTicks);
        return entry.Limiter.AttemptAcquire(1);
    }

    private Entry GetOrAddEntry(string key)
    {
        if (_partitions.TryGetValue(key, out var existing))
        {
            return existing;
        }

        lock (_mutationLock)
        {
            if (_partitions.TryGetValue(key, out existing))
            {
                return existing;
            }

            if (_partitions.Count >= _maxPartitions)
            {
                EvictLeastRecentlyUsedLocked();
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
            _partitions[key] = created;
            return created;
        }
    }

    private void EvictLeastRecentlyUsedLocked()
    {
        string? lruKey = null;
        var oldest = long.MaxValue;
        foreach (var kv in _partitions)
        {
            var last = Volatile.Read(ref kv.Value.LastAccessTicks);
            if (last < oldest)
            {
                oldest = last;
                lruKey = kv.Key;
            }
        }

        if (lruKey is not null && _partitions.TryRemove(lruKey, out var removed))
        {
            removed.Limiter.Dispose();
        }
    }

    private void SweepIdle()
    {
        if (_disposed)
        {
            return;
        }

        var cutoff = _clock.GetUtcNow().UtcTicks - _idleExpiration.Ticks;
        foreach (var kv in _partitions)
        {
            if (Volatile.Read(ref kv.Value.LastAccessTicks) < cutoff && _partitions.TryRemove(kv.Key, out var removed))
            {
                removed.Limiter.Dispose();
            }
        }
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
}
