using System.Text;
using BitosX.Application.Abstractions.Persistence;
using BitosX.Application.Accounts;
using BitosX.Application.Mfa;
using BitosX.Application.Security;
using BitosX.Application.Sessions;
using Microsoft.Extensions.Time.Testing;

namespace BitosX.Application.Tests;

public sealed class MfaLoginServiceTests
{
    private const string Phc = "$argon2id$v=19$m=8192,t=1,p=1$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYQ";
    private static readonly DateTime Now = new(2026, 10, 22, 12, 0, 0, DateTimeKind.Utc);
    private static readonly Guid AccountId = Guid.Parse("11111111-1111-1111-1111-111111111111");
    private static readonly byte[] Secret = Encoding.ASCII.GetBytes("12345678901234567890");

    private readonly FakeAccountRepository _accounts = new();
    private readonly FakeMfaChallengeStore _challenges = new();
    private readonly FakeTotpStore _totp = new();
    private readonly FakeRefreshTokenFactory _tokens = new();
    private readonly FakeSessionStore _sessions = new();
    private readonly FakeAccessTokenService _access = new();
    private readonly FakeTimeProvider _clock = new(new DateTimeOffset(Now));
    private readonly FakeTotpCrypto _crypto = new();
    private readonly TotpOptions _options = new();
    private readonly FakeMfaLimiter _limiter = new();

    private MfaLoginService Service()
    {
        _sessions.CreateResult = new LoginSessionCreateResult
        {
            Outcome = LoginSessionCreateOutcome.Created, AccountId = AccountId, SessionId = Guid.NewGuid(),
            SessionCreatedAt = Now, SessionAbsoluteExpiresAt = Now.AddDays(90), RefreshTokenExpiresAt = Now.AddDays(30),
        };
        return new MfaLoginService(_accounts, _challenges, _totp, new MfaCodeVerifier(_totp, _crypto, _options, _clock), _tokens, _sessions, _access, _limiter, _options, _clock);
    }

    private void SeedAccountAndChallenge(string? phc = Phc, bool confirmed = true)
    {
        _accounts.Seed(new Account { Id = AccountId, Email = "u@example.com", NormalizedEmail = "U@EXAMPLE.COM", EmailVerifiedAt = Now.AddDays(-1), PasswordHash = phc, CreatedAt = Now.AddDays(-2), UpdatedAt = Now.AddDays(-2) });
        _challenges.Active = new MfaChallengeView(Guid.NewGuid(), AccountId, LoginService.PasswordHashFingerprint(Phc), "Agent/1", Now.AddMinutes(4), 0);
        _totp.Enrollment = new TotpEnrollment(AccountId, _crypto.Protect(Secret, AccountId), Now.AddDays(-1), confirmed ? Now.AddDays(-1) : null, null);
    }

    private string CurrentCode() => Rfc6238Totp.Compute(Secret, Rfc6238Totp.Step(_clock.GetUtcNow().ToUnixTimeSeconds(), 30), 6);
    private static string GoodToken() => new('A', 43);

    [Fact]
    public async Task ValidTotpCode_CreatesSession_WithChallengeUserAgent_AndConsumesChallengeAndStep()
    {
        SeedAccountAndChallenge();
        var r = await Service().CompleteAsync(new MfaLoginCommand(GoodToken(), CurrentCode()));

        Assert.Equal(LoginOutcome.Succeeded, r.Outcome);
        Assert.NotNull(r.AccessToken);
        Assert.Equal(1, _totp.ConsumeStepCalls);
        Assert.Equal(1, _challenges.ConsumeCalls);
        Assert.Equal(0, _challenges.FailedAttemptCalls);
        Assert.Equal("Agent/1", _sessions.LastUserAgent);
        Assert.Equal(Phc, _sessions.LastExpectedPasswordHash);
    }

    [Fact]
    public async Task WrongCode_UsesItsReservedAttempt_NoSession()
    {
        SeedAccountAndChallenge();
        var r = await Service().CompleteAsync(new MfaLoginCommand(GoodToken(), "000000"));

        Assert.Equal(LoginOutcome.InvalidCredentials, r.Outcome);
        Assert.Equal(1, _challenges.ReserveCalls);
        Assert.Equal(1, _challenges.FailedAttemptCalls); // the close-at-limit check ran
        Assert.Equal(0, _challenges.ConsumeCalls);
        Assert.Equal(0, _sessions.CreateCalls);
    }

    [Fact]
    public async Task TheAttemptIsReservedBeforeTheCodeIsLookedAt_AndTheChallengeIsClaimedBeforeTheCodeIsSpent()
    {
        SeedAccountAndChallenge();
        var trace = new List<string>();
        _challenges.Trace = trace;
        _totp.Trace = trace;

        var r = await Service().CompleteAsync(new MfaLoginCommand(GoodToken(), "ABCDE FGHJK"));

        Assert.Equal(LoginOutcome.Succeeded, r.Outcome);
        Assert.Equal(["reserve", "consume-challenge", "consume-code"], trace);
    }

    [Fact]
    public async Task NoAttemptLeft_TheCodeIsNeverChecked()
    {
        SeedAccountAndChallenge();
        _challenges.ReserveResult = false;

        var r = await Service().CompleteAsync(new MfaLoginCommand(GoodToken(), CurrentCode()));

        Assert.Equal(LoginOutcome.InvalidCredentials, r.Outcome);
        Assert.Equal(0, _totp.GetCalls);
        Assert.Equal(0, _totp.ConsumeStepCalls);
        Assert.Equal(0, _sessions.CreateCalls);
    }

    [Fact]
    public async Task ParallelWrongCodes_GetAtMostMaxAttemptsCodeChecks()
    {
        SeedAccountAndChallenge();
        var service = Service();

        var results = await Task.WhenAll(Enumerable.Range(0, 25).Select(_ => Task.Run(() => service.CompleteAsync(new MfaLoginCommand(GoodToken(), "000000")))));

        Assert.All(results, x => Assert.Equal(LoginOutcome.InvalidCredentials, x.Outcome));
        Assert.Equal(_options.MaxMfaAttempts, _challenges.ReservedAttempts);
        Assert.Equal(_options.MaxMfaAttempts, _challenges.FailedAttemptCalls); // only reserved attempts reached the code check
        Assert.Equal(_options.MaxMfaAttempts, _totp.GetCalls);
    }

    [Fact]
    public async Task ChallengeLostToAConcurrentCompletion_DoesNotSpendTheRecoveryCode()
    {
        SeedAccountAndChallenge();
        _challenges.ConsumeResult = false;

        var r = await Service().CompleteAsync(new MfaLoginCommand(GoodToken(), "abcde-fghjk"));

        Assert.Equal(LoginOutcome.InvalidCredentials, r.Outcome);
        Assert.Equal(0, _totp.ConsumeRecoveryCalls);
        Assert.Equal(0, _sessions.CreateCalls);
    }

    [Fact]
    public async Task PerAccountLimiter_RateLimited_NoAttemptReserved()
    {
        SeedAccountAndChallenge();
        _limiter.Decision = new MfaAttemptDecision(MfaAttemptAdmission.RateLimited, TimeSpan.FromSeconds(42));

        var r = await Service().CompleteAsync(new MfaLoginCommand(GoodToken(), CurrentCode()));

        Assert.Equal(LoginOutcome.RateLimited, r.Outcome);
        Assert.Equal(TimeSpan.FromSeconds(42), r.RetryAfter);
        Assert.Equal(AccountId, _limiter.LastAccountId); // keyed by the account the challenge belongs to
        Assert.Equal(0, _challenges.ReserveCalls);
        Assert.Equal(0, _sessions.CreateCalls);
    }

    [Fact]
    public async Task PerAccountLimiter_AtCapacity_FailsClosed()
    {
        SeedAccountAndChallenge();
        _limiter.Decision = new MfaAttemptDecision(MfaAttemptAdmission.Unavailable);

        var r = await Service().CompleteAsync(new MfaLoginCommand(GoodToken(), CurrentCode()));

        Assert.Equal(LoginOutcome.TemporarilyUnavailable, r.Outcome);
        Assert.Equal(0, _challenges.ReserveCalls);
    }

    [Fact]
    public async Task UnknownToken_NeverReachesTheLimiter()
    {
        SeedAccountAndChallenge();
        _challenges.Active = null;
        await Service().CompleteAsync(new MfaLoginCommand(GoodToken(), CurrentCode()));
        Assert.Equal(0, _limiter.Calls);
    }

    private sealed class FakeMfaLimiter : IMfaAttemptLimiter
    {
        public MfaAttemptDecision Decision { get; set; } = MfaAttemptDecision.Admitted;
        public int Calls { get; private set; }
        public Guid LastAccountId { get; private set; }

        public MfaAttemptDecision TryAdmit(Guid accountId) { Calls++; LastAccountId = accountId; return Decision; }
    }

    [Fact]
    public async Task ReplayedStep_IsRejectedByTheStore()
    {
        SeedAccountAndChallenge();
        _totp.ConsumeStepResult = false; // the store says this step was already used (a concurrent use won)
        var r = await Service().CompleteAsync(new MfaLoginCommand(GoodToken(), CurrentCode()));
        Assert.Equal(LoginOutcome.InvalidCredentials, r.Outcome);
        Assert.Equal(0, _sessions.CreateCalls);
    }

    [Fact]
    public async Task AStepAtOrBelowTheLastUsedOne_DoesNotMatch()
    {
        SeedAccountAndChallenge();
        var step = Rfc6238Totp.Step(_clock.GetUtcNow().ToUnixTimeSeconds(), 30);
        _totp.Enrollment = _totp.Enrollment! with { LastUsedStep = step };
        var r = await Service().CompleteAsync(new MfaLoginCommand(GoodToken(), CurrentCode()));
        Assert.Equal(LoginOutcome.InvalidCredentials, r.Outcome);
        Assert.Equal(0, _totp.ConsumeStepCalls);
        Assert.Equal(0, _challenges.ConsumeCalls);
    }

    [Fact]
    public async Task RecoveryCode_IsAcceptedOnce_ByKeyedVerifier()
    {
        SeedAccountAndChallenge();
        var code = "abcde-fghjk";
        var r = await Service().CompleteAsync(new MfaLoginCommand(GoodToken(), "ABCDE FGHJK"));
        Assert.Equal(LoginOutcome.Succeeded, r.Outcome);
        Assert.Equal(_crypto.RecoveryCodeVerifier("abcdefghjk"), _totp.LastRecoveryVerifier);
        Assert.Equal(0, _totp.ConsumeStepCalls);

        _totp.ConsumeRecoveryResult = false; // already used
        Assert.Equal(LoginOutcome.InvalidCredentials, (await Service().CompleteAsync(new MfaLoginCommand(GoodToken(), code))).Outcome);
    }

    [Fact]
    public async Task UnknownOrMalformedToken_IsInvalid_NoLookupForMalformed()
    {
        SeedAccountAndChallenge();
        _challenges.Active = null;
        Assert.Equal(LoginOutcome.InvalidCredentials, (await Service().CompleteAsync(new MfaLoginCommand(GoodToken(), CurrentCode()))).Outcome);
        Assert.Equal(LoginOutcome.InvalidCredentials, (await Service().CompleteAsync(new MfaLoginCommand("short", CurrentCode()))).Outcome);
        Assert.Equal(0, _sessions.CreateCalls);
    }

    [Fact]
    public async Task PasswordChangedBetweenSteps_InvalidatesChallenge()
    {
        SeedAccountAndChallenge(phc: "$argon2id$v=19$m=8192,t=1,p=1$b3RoZXJzYWx0c2FsdA$b3RoZXJoYXNob3RoZXJoYXNob3RoZXI");
        var r = await Service().CompleteAsync(new MfaLoginCommand(GoodToken(), CurrentCode()));
        Assert.Equal(LoginOutcome.InvalidCredentials, r.Outcome);
        Assert.Equal(1, _challenges.ConsumeCalls); // killed, not just refused
        Assert.Equal(0, _totp.ConsumeStepCalls);
    }

    [Fact]
    public async Task TotpDisabledMeanwhile_InvalidatesChallenge()
    {
        SeedAccountAndChallenge(confirmed: false);
        var r = await Service().CompleteAsync(new MfaLoginCommand(GoodToken(), CurrentCode()));
        Assert.Equal(LoginOutcome.InvalidCredentials, r.Outcome);
        Assert.Equal(1, _challenges.ConsumeCalls);
        Assert.Equal(0, _sessions.CreateCalls);
    }

    [Fact]
    public async Task ChallengeConsumedConcurrently_NoSession()
    {
        SeedAccountAndChallenge();
        _challenges.ConsumeResult = false;
        var r = await Service().CompleteAsync(new MfaLoginCommand(GoodToken(), CurrentCode()));
        Assert.Equal(LoginOutcome.InvalidCredentials, r.Outcome);
        Assert.Equal(0, _sessions.CreateCalls);
    }
}
