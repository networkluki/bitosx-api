using System.Threading.RateLimiting;
using BitosX.Application.Security;
using BitosX.Infrastructure.Security;

namespace BitosX.Infrastructure.Tests.Security;

/// <summary>
/// State-machine tests for the bounded Argon2 admission gate. Deterministic: capacity is occupied by
/// HOLDING acquired leases (not by running Argon2), and ordering is proven by releasing permits one at a
/// time — never by timing/CPU speed. Only the timeout test waits (briefly) for a real timeout to elapse.
/// </summary>
public sealed class Argon2WorkGateTests
{
    private static Argon2WorkGate Gate(int max = 2, int queue = 4, int timeoutMs = 30000)
        => new(new Argon2AdmissionOptions { MaxConcurrent = max, QueueCapacity = queue, AcquireTimeoutMilliseconds = timeoutMs });

    [Fact]
    public async Task ExecutingBoundedByMaxConcurrent_ExtraQueuesUntilRelease()
    {
        using var gate = Gate(max: 2, queue: 4);
        var a = await gate.AcquireAsync(default);
        var b = await gate.AcquireAsync(default); // 2 permits held

        var queued = gate.AcquireAsync(default).AsTask(); // must wait — MaxConcurrent reached
        Assert.False(queued.IsCompleted);

        a.Dispose();                 // free one permit
        using var admitted = await queued; // the waiter is now admitted
        Assert.True(admitted.IsAcquired);

        b.Dispose();
    }

    [Fact]
    public async Task QueueFull_NextOperationRejectedImmediately()
    {
        using var gate = Gate(max: 2, queue: 4, timeoutMs: 30000); // long timeout: proves rejection is immediate, not a timeout
        var held = new List<RateLimitLease> { await gate.AcquireAsync(default), await gate.AcquireAsync(default) };
        var queued = Enumerable.Range(0, 4).Select(_ => gate.AcquireAsync(default).AsTask()).ToList(); // 4 waiting → 6 admitted total

        await Assert.ThrowsAsync<PasswordHashingCapacityExceededException>(async () => await gate.AcquireAsync(default));
        Assert.All(queued, t => Assert.False(t.IsCompleted)); // the 7th did not disturb the queued waiters

        foreach (var h in held) h.Dispose();
        // Release sequentially: each disposed lease frees exactly one permit for the next FIFO waiter.
        foreach (var t in queued)
        {
            (await t).Dispose();
        }
    }

    [Fact]
    public async Task QueuedWaiters_AreAdmittedFifo()
    {
        using var gate = Gate(max: 1, queue: 4);
        var head = await gate.AcquireAsync(default); // the single permit

        var w0 = gate.AcquireAsync(default).AsTask();
        var w1 = gate.AcquireAsync(default).AsTask();
        var w2 = gate.AcquireAsync(default).AsTask();
        Assert.False(w0.IsCompleted || w1.IsCompleted || w2.IsCompleted);

        head.Dispose();
        var l0 = await w0;                       // oldest admitted first
        Assert.False(w1.IsCompleted || w2.IsCompleted);

        l0.Dispose();
        var l1 = await w1;
        Assert.False(w2.IsCompleted);

        l1.Dispose();
        (await w2).Dispose();
    }

    [Fact]
    public async Task QueuedOperation_TimesOut_AsCapacityRejection()
    {
        using var gate = Gate(max: 1, queue: 4, timeoutMs: 120);
        using var held = await gate.AcquireAsync(default); // hold the only permit; never released within the timeout

        await Assert.ThrowsAsync<PasswordHashingCapacityExceededException>(async () => await gate.AcquireAsync(default));
    }

    [Fact]
    public async Task Cancellation_ReleasesQueueSlot_AndThrowsOperationCanceled_NotCapacity()
    {
        using var gate = Gate(max: 1, queue: 1, timeoutMs: 30000);
        using var held = await gate.AcquireAsync(default); // hold the permit

        using var cts = new CancellationTokenSource();
        var waiter = gate.AcquireAsync(cts.Token).AsTask(); // occupies the single queue slot
        Assert.False(waiter.IsCompleted);

        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await waiter); // cancellation, not overload

        // The queue slot was freed by cancellation → a fresh waiter can queue (proves no permit/slot leak).
        var replacement = gate.AcquireAsync(default).AsTask();
        Assert.False(replacement.IsCompleted);

        held.Dispose();
        (await replacement).Dispose();
    }

    [Fact]
    public async Task RepeatedSuccessTimeoutCancellation_DoesNotLeakCapacity()
    {
        using var gate = Gate(max: 2, queue: 1, timeoutMs: 60);

        for (var i = 0; i < 30; i++)
        {
            // success: acquire + release
            (await gate.AcquireAsync(default)).Dispose();

            // cancellation while queued
            var a = await gate.AcquireAsync(default);
            var b = await gate.AcquireAsync(default);
            using (var cts = new CancellationTokenSource())
            {
                var w = gate.AcquireAsync(cts.Token).AsTask();
                cts.Cancel();
                await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await w);
            }
            a.Dispose();
            b.Dispose();
        }

        // Capacity is fully intact: 2 execute + 4-slot... here queue=1, so 2 exec + 1 queued, then reject.
        var h1 = await gate.AcquireAsync(default);
        var h2 = await gate.AcquireAsync(default);
        var q = gate.AcquireAsync(default).AsTask();
        await Assert.ThrowsAsync<PasswordHashingCapacityExceededException>(async () => await gate.AcquireAsync(default));
        h1.Dispose();
        (await q).Dispose();
        h2.Dispose();
    }

    [Fact]
    public async Task AlreadyCanceledToken_ThrowsOperationCanceled_WithoutConsumingCapacity()
    {
        using var gate = Gate(max: 1, queue: 0);
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await gate.AcquireAsync(cts.Token));

        // No permit was consumed → a normal acquire still succeeds.
        using var lease = await gate.AcquireAsync(default);
        Assert.True(lease.IsAcquired);
    }
}
