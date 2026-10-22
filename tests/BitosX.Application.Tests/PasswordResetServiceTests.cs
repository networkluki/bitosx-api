using BitosX.Application.Abstractions.Persistence;
using BitosX.Application.Accounts;
using BitosX.Application.Email;
using BitosX.Application.Verification;
using Microsoft.Extensions.Time.Testing;

namespace BitosX.Application.Tests;

public sealed class PasswordResetServiceTests
{
    private readonly FakeAccountRepository _accounts = new();
    private readonly FakePasswordResetStore _store = new();
    private readonly SpyPasswordHasher _hasher = new();
    private readonly FakeTimeProvider _clock = new(DateTimeOffset.Parse("2026-10-22T12:00:00Z"));

    private const string ValidPw = "correct-horse-12";
    private const string Phc = "$argon2id$v=19$m=8192,t=1,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYQ";

    private PasswordResetService Service()
    {
        var options = new EmailVerificationSecurityOptions { Pepper = "x" };
        var factory = new VerificationChallengeFactory(new FakeTokenFactory(), new FakeOutboxPayloadProtector(), options);
        return new PasswordResetService(_accounts, _store, new FakeTokenFactory(), factory, _hasher, options, _clock);
    }

    private Account Verified(string email) => new()
    {
        Id = Guid.NewGuid(), Email = email, NormalizedEmail = EmailNormalizer.Normalize(email),
        EmailVerifiedAt = _clock.GetUtcNow().UtcDateTime, PasswordHash = Phc,
        CreatedAt = _clock.GetUtcNow().UtcDateTime, UpdatedAt = _clock.GetUtcNow().UtcDateTime,
    };

    // ---- request (forgot-password) ----

    [Fact]
    public async Task Request_VerifiedAccount_IssuesResetChallenge_ToAccountEmail()
    {
        _accounts.Seed(Verified("User@Example.com"));

        var r = await Service().RequestAsync(new ForgotPasswordCommand("user@example.com"));

        Assert.Equal(ForgotPasswordResult.Accepted, r);
        Assert.Equal(1, _store.IssueCalls);
        Assert.Equal(ChallengePurposes.PasswordReset, _store.LastIssuedChallenge!.Purpose);
        Assert.Equal(OutboxMessageTypes.PasswordReset, _store.LastIssuedOutbox!.MessageType);
        Assert.Equal("User@Example.com", _store.LastIssuedOutbox.RecipientEmail); // the stored address, not the typed one
        Assert.Equal(0, _hasher.HashCalls);
    }

    [Fact]
    public async Task Request_UnverifiedAccount_NoChallenge_StillAccepted()
    {
        var now = _clock.GetUtcNow().UtcDateTime;
        _accounts.Seed(new Account { Id = Guid.NewGuid(), Email = "u@example.com", NormalizedEmail = "U@EXAMPLE.COM", CreatedAt = now, UpdatedAt = now });

        Assert.Equal(ForgotPasswordResult.Accepted, await Service().RequestAsync(new ForgotPasswordCommand("u@example.com")));
        Assert.Equal(0, _store.IssueCalls);
    }

    [Fact]
    public async Task Request_DisabledAccount_NoChallenge_StillAccepted()
    {
        _accounts.Seed(Verified("d@example.com") with { DisabledAt = _clock.GetUtcNow().UtcDateTime });

        Assert.Equal(ForgotPasswordResult.Accepted, await Service().RequestAsync(new ForgotPasswordCommand("d@example.com")));
        Assert.Equal(0, _store.IssueCalls);
    }

    [Fact]
    public async Task Request_UnknownOrInvalidEmail_NoChallenge_StillAccepted()
    {
        Assert.Equal(ForgotPasswordResult.Accepted, await Service().RequestAsync(new ForgotPasswordCommand("nobody@example.com")));
        Assert.Equal(ForgotPasswordResult.Accepted, await Service().RequestAsync(new ForgotPasswordCommand("not-an-email")));
        Assert.Equal(0, _store.IssueCalls);
    }

    [Theory]
    [InlineData(PasswordResetIssueOutcome.SkippedTooSoon)]
    [InlineData(PasswordResetIssueOutcome.SkippedDeliveryInProgress)]
    [InlineData(PasswordResetIssueOutcome.AccountNotEligible)]
    public async Task Request_StoreSkips_StillAccepted(PasswordResetIssueOutcome outcome)
    {
        _accounts.Seed(Verified("v@example.com"));
        _store.IssueOutcome = outcome;

        Assert.Equal(ForgotPasswordResult.Accepted, await Service().RequestAsync(new ForgotPasswordCommand("v@example.com")));
    }

    // ---- reset ----

    [Fact]
    public async Task Reset_InvalidPassword_NoHashing_NoLookup()
    {
        var r = await Service().ResetAsync(new ResetPasswordCommand("sometoken", "short"));
        Assert.Equal(ResetPasswordResult.InvalidPassword, r);
        Assert.Equal(0, _hasher.HashCalls);
        Assert.Equal(0, _store.FindCalls);
        Assert.Equal(0, _store.FinalizeCalls);
    }

    [Fact]
    public async Task Reset_MalformedOrEmptyToken_NoHashing_ReturnsInvalid()
    {
        Assert.Equal(ResetPasswordResult.Invalid, await Service().ResetAsync(new ResetPasswordCommand("bad!token", ValidPw)));
        Assert.Equal(ResetPasswordResult.Invalid, await Service().ResetAsync(new ResetPasswordCommand("", ValidPw)));
        Assert.Equal(0, _hasher.HashCalls);
        Assert.Equal(0, _store.FindCalls);
    }

    [Fact]
    public async Task Reset_UnknownToken_NoHashing_ReturnsInvalid()
    {
        _store.ActiveToReturn = null;
        var r = await Service().ResetAsync(new ResetPasswordCommand("sometoken", ValidPw));
        Assert.Equal(ResetPasswordResult.Invalid, r);
        Assert.Equal(0, _hasher.HashCalls); // pre-check gate: no CPU amplification
        Assert.Equal(0, _store.FinalizeCalls);
    }

    [Fact]
    public async Task Reset_Valid_HashesOnce_AndFinalizesWithThatHash()
    {
        _store.ActiveToReturn = new ActiveChallengeView(Guid.NewGuid(), Guid.NewGuid(), _clock.GetUtcNow().UtcDateTime.AddMinutes(10));
        _store.FinalizeOutcome = PasswordResetOutcome.Reset;

        var r = await Service().ResetAsync(new ResetPasswordCommand("sometoken", ValidPw));

        Assert.Equal(ResetPasswordResult.Reset, r);
        Assert.Equal(1, _hasher.HashCalls);
        Assert.Equal(1, _store.FinalizeCalls);
        Assert.StartsWith("$argon2id$", _store.LastFinalizedPhc);
    }

    [Fact]
    public async Task Reset_TwoPhaseRace_FinalizeFails_ReturnsInvalid()
    {
        _store.ActiveToReturn = new ActiveChallengeView(Guid.NewGuid(), Guid.NewGuid(), _clock.GetUtcNow().UtcDateTime.AddMinutes(10));
        _store.FinalizeOutcome = PasswordResetOutcome.InvalidOrExpired;

        var r = await Service().ResetAsync(new ResetPasswordCommand("sometoken", ValidPw));

        Assert.Equal(ResetPasswordResult.Invalid, r);
        Assert.Equal(1, _hasher.HashCalls);
        Assert.Equal(1, _store.FinalizeCalls);
    }
}
