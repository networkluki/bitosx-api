using BitosX.Application.Abstractions.Persistence;
using BitosX.Application.Accounts;
using BitosX.Application.Verification;
using Microsoft.Extensions.Time.Testing;

namespace BitosX.Application.Tests;

public sealed class EmailVerificationServiceTests
{
    private readonly FakeAccountRepository _accounts = new();
    private readonly FakeVerificationStore _store = new();
    private readonly SpyPasswordHasher _hasher = new();
    private readonly FakeTimeProvider _clock = new(DateTimeOffset.Parse("2026-09-16T12:00:00Z"));

    private EmailVerificationService Service()
    {
        var factory = new VerificationChallengeFactory(new FakeTokenFactory(), new FakeOutboxPayloadProtector(),
            new EmailVerificationSecurityOptions { Pepper = "x" });
        return new EmailVerificationService(_accounts, _store, new FakeTokenFactory(), factory, _hasher,
            new EmailVerificationSecurityOptions { Pepper = "x" }, _clock);
    }

    private const string ValidPw = "correct-horse-12";

    [Fact]
    public async Task Verify_InvalidPassword_NoHashing_NoFinalize()
    {
        var r = await Service().VerifyAsync(new VerifyEmailCommand("sometoken", "short"));
        Assert.Equal(VerifyResult.InvalidPassword, r);
        Assert.Equal(0, _hasher.HashCalls);
        Assert.Equal(0, _store.FinalizeCalls);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public async Task Verify_MissingToken_IsInvalid_WithoutLookupOrHashing(string? token)
    {
        _store.ActiveToReturn = new ActiveChallengeView(Guid.NewGuid(), Guid.NewGuid(), _clock.GetUtcNow().UtcDateTime.AddMinutes(10));
        var r = await Service().VerifyAsync(new VerifyEmailCommand(token!, ValidPw));
        Assert.Equal(VerifyResult.Invalid, r);
        Assert.Equal(0, _hasher.HashCalls);
        Assert.Equal(0, _store.FinalizeCalls);
    }

    [Fact]
    public async Task Verify_BogusToken_NoHashing_ReturnsInvalid()
    {
        _store.ActiveToReturn = null; // Phase A finds no active challenge
        var r = await Service().VerifyAsync(new VerifyEmailCommand("sometoken", ValidPw));
        Assert.Equal(VerifyResult.Invalid, r);
        Assert.Equal(0, _hasher.HashCalls); // Phase A gate: no CPU amplification
        Assert.Equal(0, _store.FinalizeCalls);
    }

    [Fact]
    public async Task Verify_Valid_HashesOnce_AndFinalizes()
    {
        _store.ActiveToReturn = new ActiveChallengeView(Guid.NewGuid(), Guid.NewGuid(), _clock.GetUtcNow().UtcDateTime.AddMinutes(10));
        _store.FinalizeOutcome = VerificationOutcome.Verified;

        var r = await Service().VerifyAsync(new VerifyEmailCommand("sometoken", ValidPw));

        Assert.Equal(VerifyResult.Verified, r);
        Assert.Equal(1, _hasher.HashCalls);
        Assert.Equal(1, _store.FinalizeCalls);
    }

    [Fact]
    public async Task Verify_TwoPhaseRace_FinalizeFails_ReturnsInvalid()
    {
        // Pre-check passes, but state changed before Phase C → Finalize InvalidOrExpired.
        _store.ActiveToReturn = new ActiveChallengeView(Guid.NewGuid(), Guid.NewGuid(), _clock.GetUtcNow().UtcDateTime.AddMinutes(10));
        _store.FinalizeOutcome = VerificationOutcome.InvalidOrExpired;

        var r = await Service().VerifyAsync(new VerifyEmailCommand("sometoken", ValidPw));

        Assert.Equal(VerifyResult.Invalid, r);
        Assert.Equal(1, _hasher.HashCalls);   // hashing happened (Phase B) ...
        Assert.Equal(1, _store.FinalizeCalls); // ... but Phase C rejected → no partial activation
    }

    [Fact]
    public async Task Resend_UnverifiedAccount_CallsReplace()
    {
        var now = _clock.GetUtcNow().UtcDateTime;
        _accounts.Seed(new Account { Id = Guid.NewGuid(), Email = "u@example.com", NormalizedEmail = "U@EXAMPLE.COM", CreatedAt = now, UpdatedAt = now });
        var r = await Service().ResendAsync(new ResendCommand("u@example.com"));
        Assert.Equal(ResendResult.Accepted, r);
        Assert.Equal(1, _store.ReplaceCalls);
    }

    [Fact]
    public async Task Resend_VerifiedAccount_NoReplace_StillAccepted()
    {
        var now = _clock.GetUtcNow().UtcDateTime;
        _accounts.Seed(new Account { Id = Guid.NewGuid(), Email = "v@example.com", NormalizedEmail = "V@EXAMPLE.COM", EmailVerifiedAt = now, CreatedAt = now, UpdatedAt = now });
        var r = await Service().ResendAsync(new ResendCommand("v@example.com"));
        Assert.Equal(ResendResult.Accepted, r);
        Assert.Equal(0, _store.ReplaceCalls);
    }

    [Fact]
    public async Task Resend_UnknownOrInvalid_NoReplace_StillAccepted()
    {
        Assert.Equal(ResendResult.Accepted, await Service().ResendAsync(new ResendCommand("nobody@example.com")));
        Assert.Equal(ResendResult.Accepted, await Service().ResendAsync(new ResendCommand("not-an-email")));
        Assert.Equal(0, _store.ReplaceCalls);
    }
}
