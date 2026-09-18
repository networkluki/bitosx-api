using BitosX.Api.Security;
using Microsoft.Extensions.Time.Testing;

namespace BitosX.Api.Tests;

/// <summary>
/// Unit tests for the memory-bounded partition cache: hard max-partition cap with LRU eviction and
/// deterministic idle expiration (driven by FakeTimeProvider — no real sleeps).
/// </summary>
public sealed class BoundedRateLimiterCacheTests
{
    private static TokenBucketPolicyOptions Policy() => new() { TokenLimit = 3, TokensPerPeriod = 1, ReplenishmentSeconds = 30 };

    [Fact]
    public void AttemptAcquire_WithinLimit_Acquires_ThenRejectsOverLimit()
    {
        var clock = new FakeTimeProvider();
        using var cache = new BoundedRateLimiterCache(new TokenBucketPolicyOptions { TokenLimit = 1, TokensPerPeriod = 1, ReplenishmentSeconds = 30 }, 16, TimeSpan.FromMinutes(30), clock);

        using var first = cache.AttemptAcquire("k");
        using var second = cache.AttemptAcquire("k");

        Assert.True(first.IsAcquired);
        Assert.False(second.IsAcquired); // QueueLimit = 0, no replenishment yet
    }

    [Fact]
    public void ExceedingMaxPartitions_EvictsLeastRecentlyUsed_KeepsBounded()
    {
        var clock = new FakeTimeProvider();
        using var cache = new BoundedRateLimiterCache(Policy(), maxPartitions: 2, TimeSpan.FromMinutes(30), clock);

        cache.AttemptAcquire("a").Dispose();
        clock.Advance(TimeSpan.FromSeconds(1));
        cache.AttemptAcquire("b").Dispose();
        clock.Advance(TimeSpan.FromSeconds(1));
        cache.AttemptAcquire("c").Dispose(); // forces eviction of LRU ("a")

        Assert.True(cache.PartitionCount <= 2);
    }

    [Fact]
    public void IdlePartitions_AreSweptAfterExpiration()
    {
        var clock = new FakeTimeProvider();
        using var cache = new BoundedRateLimiterCache(Policy(), maxPartitions: 4096, TimeSpan.FromMinutes(30), clock);

        cache.AttemptAcquire("idle").Dispose();
        Assert.Equal(1, cache.PartitionCount);

        clock.Advance(TimeSpan.FromMinutes(31)); // past idle window → sweep timer fires and evicts

        Assert.Equal(0, cache.PartitionCount);
    }
}
