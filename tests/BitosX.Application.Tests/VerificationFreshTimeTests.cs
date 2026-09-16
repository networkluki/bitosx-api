using BitosX.Application.Abstractions.Persistence;
using BitosX.Application.Verification;
using Microsoft.Extensions.Time.Testing;

namespace BitosX.Application.Tests;

/// <summary>Fix 1: the authoritative finalize must use a fresh timestamp captured AFTER hashing.</summary>
public sealed class VerificationFreshTimeTests
{
    [Fact]
    public async Task Verify_UsesPostHashTimestamp_ForFinalize_NotPrecheckTime()
    {
        var start = DateTimeOffset.Parse("2026-09-16T12:00:00Z");
        var clock = new FakeTimeProvider(start);
        var store = new FakeVerificationStore
        {
            ActiveToReturn = new ActiveChallengeView(Guid.NewGuid(), Guid.NewGuid(), start.UtcDateTime.AddMinutes(10)),
            FinalizeOutcome = VerificationOutcome.Verified,
        };
        var hasher = new AdvancingHasher(clock, TimeSpan.FromMilliseconds(200)); // Argon2 "takes" 200ms
        var factory = new VerificationChallengeFactory(new FakeTokenFactory(), new FakeOutboxPayloadProtector(),
            new EmailVerificationSecurityOptions { Pepper = "x" });
        var service = new EmailVerificationService(new FakeAccountRepository(), store, new FakeTokenFactory(), factory,
            hasher, new EmailVerificationSecurityOptions { Pepper = "x" }, clock);

        await service.VerifyAsync(new VerifyEmailCommand("sometoken", "valid-password-12"));

        // Pre-check saw T; finalize must see T+200ms (fresh), not the stale pre-check time.
        Assert.Equal(start.UtcDateTime, store.PrecheckNow);
        Assert.Equal(start.UtcDateTime.AddMilliseconds(200), store.FinalizeNow);
        Assert.True(store.FinalizeNow > store.PrecheckNow);
    }
}
