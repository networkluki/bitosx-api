using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;
using BitosX.Api.Security;
using Microsoft.Extensions.Time.Testing;

namespace BitosX.Api.Tests;

/// <summary>
/// Unit tests for the memory-bounded partition cache, focused on the security invariant that partition
/// churn cannot reset a live (non-idle) limiter. MaxPartitions is a memory bound, not a reset lever:
/// live entries are never evicted, and a new key fails closed when the cache is full with no idle entry.
/// Idle expiration is driven by FakeTimeProvider — no real sleeps.
/// </summary>
public sealed class BoundedRateLimiterCacheTests
{
    private static readonly TimeSpan Idle = TimeSpan.FromMinutes(30);

    private static TokenBucketPolicyOptions OneTokenPolicy() => new() { TokenLimit = 1, TokensPerPeriod = 1, ReplenishmentSeconds = 30 };
    private static TokenBucketPolicyOptions RoomyPolicy() => new() { TokenLimit = 5, TokensPerPeriod = 1, ReplenishmentSeconds = 30 };

    private static bool Acquired(BoundedRateLimiterCache cache, string key)
    {
        Assert.True(cache.TryAcquire(key, out var lease), "expected the key to be admitted (not capacity-exhausted)");
        using (lease) return lease.IsAcquired;
    }

    [Fact]
    public void ExistingKey_ResolvesAndRejects_WithinItsOwnBucket()
    {
        var clock = new FakeTimeProvider();
        using var cache = new BoundedRateLimiterCache(OneTokenPolicy(), 16, Idle, clock);

        Assert.True(Acquired(cache, "k"));   // first token
        Assert.False(Acquired(cache, "k"));  // exhausted, no replenishment yet
    }

    [Fact]
    public void PartitionChurn_DoesNotReset_AnExhaustedNonIdleLimiter()
    {
        var clock = new FakeTimeProvider();
        using var cache = new BoundedRateLimiterCache(OneTokenPolicy(), maxPartitions: 2, Idle, clock);

        Assert.True(Acquired(cache, "A"));   // A exhausted (limit 1)
        Assert.True(cache.TryAcquire("B", out var lb)); lb.Dispose(); // cache now full (A, B), both non-idle

        // New keys arrive while the cache is full and nothing is idle → they fail closed (503 at HTTP).
        Assert.False(cache.TryAcquire("C", out _));
        Assert.False(cache.TryAcquire("D", out _));

        // A must NOT have been evicted/reset by that churn: it is still exhausted.
        Assert.True(cache.TryAcquire("A", out var la));
        using (la) Assert.False(la.IsAcquired);
    }

    [Fact]
    public void FullCache_AllNonIdle_NewKeyFailsClosed_NoLiveEntryEvicted()
    {
        var clock = new FakeTimeProvider();
        using var cache = new BoundedRateLimiterCache(RoomyPolicy(), maxPartitions: 2, Idle, clock);

        Assert.True(cache.TryAcquire("A", out var la)); la.Dispose();
        Assert.True(cache.TryAcquire("B", out var lb)); lb.Dispose();
        Assert.Equal(2, cache.PartitionCount);

        Assert.False(cache.TryAcquire("C", out _)); // fail closed
        Assert.Equal(2, cache.PartitionCount);       // no live entry evicted to admit C
    }

    [Fact]
    public void AfterIdleExpiration_IdleEntriesReclaimed_NewKeyAdmitted()
    {
        var clock = new FakeTimeProvider();
        using var cache = new BoundedRateLimiterCache(RoomyPolicy(), maxPartitions: 2, Idle, clock);

        Assert.True(cache.TryAcquire("A", out var la)); la.Dispose();
        Assert.True(cache.TryAcquire("B", out var lb)); lb.Dispose();
        Assert.False(cache.TryAcquire("C", out _)); // full, non-idle

        clock.Advance(Idle + TimeSpan.FromMinutes(1)); // A and B cross the idle threshold

        Assert.True(cache.TryAcquire("C", out var lc)); // reclaimed capacity → C admitted
        using (lc) Assert.True(lc.IsAcquired);
        Assert.True(cache.PartitionCount <= 2);
    }

    [Fact]
    public void IdlePartitions_AreSweptByTimer()
    {
        var clock = new FakeTimeProvider();
        using var cache = new BoundedRateLimiterCache(RoomyPolicy(), maxPartitions: 4096, Idle, clock);

        cache.TryAcquire("idle", out var l); l.Dispose();
        Assert.Equal(1, cache.PartitionCount);

        clock.Advance(Idle + TimeSpan.FromMinutes(1)); // sweep timer fires past the idle window

        Assert.Equal(0, cache.PartitionCount);
    }

    [Fact]
    public async Task ConcurrentAcquire_NeverRacesDisposal_NoUseAfterDispose()
    {
        var clock = new FakeTimeProvider();
        // Tiny idle window so reclamation/disposal is constantly eligible; huge token limit so acquisition
        // itself never rejects (we are probing lifetime, not the rate decision).
        using var cache = new BoundedRateLimiterCache(
            new TokenBucketPolicyOptions { TokenLimit = 1_000_000, TokensPerPeriod = 1, ReplenishmentSeconds = 30 },
            maxPartitions: 64, TimeSpan.FromMilliseconds(10), clock);

        const int workers = 8;
        const int iterations = 1000;
        var keys = Enumerable.Range(0, 16).Select(i => $"k{i}").ToArray();
        var errors = new ConcurrentQueue<Exception>();
        var barrier = new Barrier(workers + 1);

        var acquirers = Enumerable.Range(0, workers).Select(w => Task.Run(() =>
        {
            barrier.SignalAndWait();
            try
            {
                for (var i = 0; i < iterations; i++)
                {
                    if (cache.TryAcquire(keys[(w + i) % keys.Length], out var lease))
                    {
                        lease.Dispose();
                    }
                }
            }
            catch (Exception ex)
            {
                errors.Enqueue(ex); // e.g. ObjectDisposedException would appear here on a racy implementation
            }
        })).ToArray();

        var churner = Task.Run(() =>
        {
            barrier.SignalAndWait();
            try
            {
                for (var i = 0; i < iterations; i++)
                {
                    clock.Advance(TimeSpan.FromSeconds(31)); // fires the idle sweep (disposes) + ages every entry
                    if (cache.TryAcquire($"new-{i}", out var lease)) // insert churn → reclaim path disposal
                    {
                        lease.Dispose();
                    }
                }
            }
            catch (Exception ex)
            {
                errors.Enqueue(ex);
            }
        });

        await Task.WhenAll([.. acquirers, churner]);

        Assert.Empty(errors); // no use-after-dispose / ObjectDisposedException
        Assert.True(cache.PartitionCount <= 64);
    }

    [Fact]
    public void ConcurrentInsertion_NeverExceedsMaxPartitions()
    {
        var clock = new FakeTimeProvider();
        const int max = 32;
        using var cache = new BoundedRateLimiterCache(RoomyPolicy(), maxPartitions: max, Idle, clock);

        var admittedKeys = new ConcurrentBag<string>();
        Parallel.For(0, 512, i =>
        {
            var key = $"k-{i}";
            if (cache.TryAcquire(key, out var lease))
            {
                admittedKeys.Add(key);
                lease.Dispose();
            }
        });

        Assert.True(cache.PartitionCount <= max, $"partition count {cache.PartitionCount} exceeded max {max}");
        // No idle entries exist during the burst, so at most `max` distinct keys can ever be admitted.
        Assert.True(admittedKeys.Distinct().Count() <= max);
    }
}
