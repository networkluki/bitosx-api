using BitosX.Application.Abstractions.Persistence;
using BitosX.Application.Security;
using BitosX.Application.Verification;
using BitosX.Infrastructure.Persistence;
using Dapper;

namespace BitosX.Infrastructure.Tests;

/// <summary>
/// Store-level tests for password reset against the test DB: purpose binding (a verification token can
/// never reset and a reset token can never verify), eligibility, single use, invalidation of siblings,
/// session revocation inside the finalize transaction, and the authoritative-time expiry rule.
/// </summary>
[Collection("Persistence")]
public sealed class PasswordResetStoreTests
{
    private readonly DatabaseFixture _fixture;
    private readonly AccountsTestContext _ctx;
    private readonly PasswordResetStore _resets;
    private readonly SessionStore _sessions;

    public PasswordResetStoreTests(DatabaseFixture fixture)
    {
        _fixture = fixture;
        _ctx = new AccountsTestContext(fixture.ConnectionFactory);
        _resets = new PasswordResetStore(fixture.ConnectionFactory, _ctx.Clock);
        _sessions = new SessionStore(fixture.ConnectionFactory, _ctx.Clock, new RefreshTokenOptions());
    }

    private VerificationChallengeFactory Factory() => new(_ctx.Tokens, _ctx.Protector, new EmailVerificationSecurityOptions { Pepper = "x" });

    private async Task<T> ScalarAsync<T>(string sql, object p)
    {
        await using var c = await _fixture.ConnectionFactory.OpenConnectionAsync();
        return (T)Convert.ChangeType(await c.ExecuteScalarAsync(new CommandDefinition(sql, p)) ?? 0L, typeof(T));
    }

    /// <summary>Registers and verifies an account (password set) through the real stores.</summary>
    private async Task<(Guid AccountId, string Email, string Phc)> VerifiedAccountAsync(DateTime now)
    {
        var r = await _ctx.RegisterAsync(now);
        var phc = await _ctx.Hasher.HashAsync("Correct-Horse-Battery-Staple-1");
        Assert.Equal(VerificationOutcome.Verified, await _ctx.VerificationStore.FinalizeVerificationAsync(r.Verifier, phc));
        return (r.AccountId, r.Email, phc);
    }

    private async Task<Guid> OpenSessionAsync(Guid accountId, string email, string phc, byte seed)
    {
        var result = await _sessions.CreateOnLoginAsync(new LoginSessionCreateRequest
        {
            AccountId = accountId, NormalizedEmail = Application.Accounts.EmailNormalizer.Normalize(email),
            ExpectedPasswordHash = phc, InitialRefreshVerifier = Enumerable.Repeat(seed, 32).ToArray(),
        });
        Assert.Equal(LoginSessionCreateOutcome.Created, result.Outcome);
        return result.SessionId;
    }

    [Fact]
    public async Task Issue_UnverifiedAccount_NotEligible_NothingInserted()
    {
        await _fixture.ResetAsync();
        var now = AccountsTestContext.NowMicro();
        var r = await _ctx.RegisterAsync(now); // unverified, no password

        var prepared = Factory().CreatePasswordReset(r.AccountId, r.Email, now);
        var outcome = await _resets.IssueChallengeAsync(r.AccountId, prepared.Challenge, prepared.Outbox, now, TimeSpan.Zero);

        Assert.Equal(PasswordResetIssueOutcome.AccountNotEligible, outcome);
        Assert.Equal(0L, await ScalarAsync<long>("SELECT COUNT(*) FROM email_verification_challenges WHERE account_id=@a AND purpose='password_reset'", new { a = r.AccountId }));
    }

    [Fact]
    public async Task Issue_RejectsNonResetChallenge()
    {
        await _fixture.ResetAsync();
        var now = AccountsTestContext.NowMicro();
        var (accountId, email, _) = await VerifiedAccountAsync(now);
        var verification = Factory().Create(accountId, email, now); // wrong purpose

        await Assert.ThrowsAsync<ArgumentException>(() =>
            _resets.IssueChallengeAsync(accountId, verification.Challenge, verification.Outbox, now, TimeSpan.Zero));
    }

    [Fact]
    public async Task Issue_SecondRequest_InvalidatesFirst_RespectsMinInterval()
    {
        await _fixture.ResetAsync();
        var now = AccountsTestContext.NowMicro();
        var (accountId, email, _) = await VerifiedAccountAsync(now);

        var first = Factory().CreatePasswordReset(accountId, email, now);
        Assert.Equal(PasswordResetIssueOutcome.Issued, await _resets.IssueChallengeAsync(accountId, first.Challenge, first.Outbox, now, TimeSpan.FromSeconds(60)));

        // Too soon → skipped, first stays active.
        var tooSoon = Factory().CreatePasswordReset(accountId, email, now.AddSeconds(10));
        Assert.Equal(PasswordResetIssueOutcome.SkippedTooSoon, await _resets.IssueChallengeAsync(accountId, tooSoon.Challenge, tooSoon.Outbox, now.AddSeconds(10), TimeSpan.FromSeconds(60)));
        Assert.Equal(1L, await ScalarAsync<long>("SELECT COUNT(*) FROM email_verification_challenges WHERE id=@id AND invalidated_at IS NULL", new { id = first.Challenge.Id }));

        // After the interval → first invalidated, second active; the verification challenge is untouched.
        var later = now.AddSeconds(61);
        var second = Factory().CreatePasswordReset(accountId, email, later);
        Assert.Equal(PasswordResetIssueOutcome.Issued, await _resets.IssueChallengeAsync(accountId, second.Challenge, second.Outbox, later, TimeSpan.FromSeconds(60)));
        Assert.Equal(1L, await ScalarAsync<long>("SELECT COUNT(*) FROM email_verification_challenges WHERE id=@id AND invalidated_at IS NOT NULL", new { id = first.Challenge.Id }));
        Assert.Equal(1L, await ScalarAsync<long>("SELECT COUNT(*) FROM email_verification_challenges WHERE account_id=@a AND purpose='email_verification' AND consumed_at IS NOT NULL AND invalidated_at IS NULL", new { a = accountId }));
        Assert.Null(await _resets.FindActiveChallengeByVerifierAsync(first.Challenge.TokenHash, later));
        Assert.NotNull(await _resets.FindActiveChallengeByVerifierAsync(second.Challenge.TokenHash, later));
    }

    [Fact]
    public async Task VerificationToken_CannotReset_AndResetToken_CannotVerify()
    {
        await _fixture.ResetAsync();
        var now = AccountsTestContext.NowMicro();
        var unverified = await _ctx.RegisterAsync(now);

        // A live verification verifier is unknown to the reset store (purpose + eligibility).
        Assert.Null(await _resets.FindActiveChallengeByVerifierAsync(unverified.Verifier, now));
        Assert.Equal(PasswordResetOutcome.InvalidOrExpired, await _resets.FinalizeResetAsync(unverified.Verifier, "$argon2id$v=19$m=8192,t=1,p=1$c2FsdA$aGFzaA"));
        Assert.Equal(1L, await ScalarAsync<long>("SELECT COUNT(*) FROM accounts WHERE id=@id AND password_hash IS NULL", new { id = unverified.AccountId }));

        // A live reset verifier is unknown to the verification store.
        var (accountId, email, _) = await VerifiedAccountAsync(now);
        var reset = Factory().CreatePasswordReset(accountId, email, now);
        Assert.Equal(PasswordResetIssueOutcome.Issued, await _resets.IssueChallengeAsync(accountId, reset.Challenge, reset.Outbox, now, TimeSpan.Zero));
        Assert.Null(await _ctx.VerificationStore.FindActiveChallengeByVerifierAsync(reset.Challenge.TokenHash, now));
        Assert.Equal(VerificationOutcome.InvalidOrExpired, await _ctx.VerificationStore.FinalizeVerificationAsync(reset.Challenge.TokenHash, "$argon2id$v=19$m=8192,t=1,p=1$c2FsdA$aGFzaA"));
    }

    [Fact]
    public async Task Finalize_ReplacesHash_ConsumesToken_InvalidatesSiblings_RevokesAllSessions()
    {
        await _fixture.ResetAsync();
        var now = AccountsTestContext.NowMicro();
        _ctx.Clock.SetUtcNow(now);
        var (accountId, email, oldPhc) = await VerifiedAccountAsync(now);
        var s1 = await OpenSessionAsync(accountId, email, oldPhc, 0x11);
        var s2 = await OpenSessionAsync(accountId, email, oldPhc, 0x12);

        var reset = Factory().CreatePasswordReset(accountId, email, now);
        Assert.Equal(PasswordResetIssueOutcome.Issued, await _resets.IssueChallengeAsync(accountId, reset.Challenge, reset.Outbox, now, TimeSpan.Zero));
        var newPhc = await _ctx.Hasher.HashAsync("Another-Strong-Password-22");

        Assert.Equal(PasswordResetOutcome.Reset, await _resets.FinalizeResetAsync(reset.Challenge.TokenHash, newPhc));

        Assert.Equal(newPhc, await ScalarAsync<string>("SELECT password_hash FROM accounts WHERE id=@id", new { id = accountId }));
        Assert.Equal(1L, await ScalarAsync<long>("SELECT COUNT(*) FROM email_verification_challenges WHERE id=@id AND consumed_at IS NOT NULL", new { id = reset.Challenge.Id }));
        Assert.Equal(0L, await ScalarAsync<long>("SELECT COUNT(*) FROM sessions WHERE account_id=@a AND revoked_at IS NULL", new { a = accountId }));
        Assert.Equal(0L, await ScalarAsync<long>("SELECT COUNT(*) FROM refresh_tokens r JOIN sessions s ON s.id=r.session_id WHERE s.account_id=@a AND r.revoked_at IS NULL", new { a = accountId }));
        Assert.NotNull((await _sessions.GetSessionAuthStateAsync(s1))!.RevokedAt);
        Assert.NotNull((await _sessions.GetSessionAuthStateAsync(s2))!.RevokedAt);

        // Single use.
        Assert.Equal(PasswordResetOutcome.InvalidOrExpired, await _resets.FinalizeResetAsync(reset.Challenge.TokenHash, newPhc));
        Assert.Null(await _resets.FindActiveChallengeByVerifierAsync(reset.Challenge.TokenHash, now));
    }

    [Fact]
    public async Task Finalize_ExpiredAgainstAuthoritativeClock_RejectsWithoutChange()
    {
        await _fixture.ResetAsync();
        var now = AccountsTestContext.NowMicro();
        _ctx.Clock.SetUtcNow(now);
        var (accountId, email, oldPhc) = await VerifiedAccountAsync(now);
        var reset = Factory().CreatePasswordReset(accountId, email, now); // 30 min TTL
        Assert.Equal(PasswordResetIssueOutcome.Issued, await _resets.IssueChallengeAsync(accountId, reset.Challenge, reset.Outbox, now, TimeSpan.Zero));

        // Pre-check passed at `now`; the store's own clock has moved past expiry by finalize time.
        Assert.NotNull(await _resets.FindActiveChallengeByVerifierAsync(reset.Challenge.TokenHash, now));
        _ctx.Clock.SetUtcNow(now.AddMinutes(31));

        Assert.Equal(PasswordResetOutcome.InvalidOrExpired, await _resets.FinalizeResetAsync(reset.Challenge.TokenHash, "$argon2id$v=19$m=8192,t=1,p=1$c2FsdA$aGFzaA"));
        Assert.Equal(oldPhc, await ScalarAsync<string>("SELECT password_hash FROM accounts WHERE id=@id", new { id = accountId }));
        Assert.Equal(1L, await ScalarAsync<long>("SELECT COUNT(*) FROM email_verification_challenges WHERE id=@id AND consumed_at IS NULL", new { id = reset.Challenge.Id }));
    }

    [Fact]
    public async Task Finalize_DisabledAccount_Rejected()
    {
        await _fixture.ResetAsync();
        var now = AccountsTestContext.NowMicro();
        _ctx.Clock.SetUtcNow(now);
        var (accountId, email, oldPhc) = await VerifiedAccountAsync(now);
        var reset = Factory().CreatePasswordReset(accountId, email, now);
        Assert.Equal(PasswordResetIssueOutcome.Issued, await _resets.IssueChallengeAsync(accountId, reset.Challenge, reset.Outbox, now, TimeSpan.Zero));

        await using (var c = await _fixture.ConnectionFactory.OpenConnectionAsync())
        {
            await c.ExecuteAsync("UPDATE accounts SET disabled_at=@now WHERE id=@id", new { now, id = accountId });
        }

        Assert.Null(await _resets.FindActiveChallengeByVerifierAsync(reset.Challenge.TokenHash, now));
        Assert.Equal(PasswordResetOutcome.InvalidOrExpired, await _resets.FinalizeResetAsync(reset.Challenge.TokenHash, "$argon2id$v=19$m=8192,t=1,p=1$c2FsdA$aGFzaA"));
        Assert.Equal(oldPhc, await ScalarAsync<string>("SELECT password_hash FROM accounts WHERE id=@id", new { id = accountId }));
    }
}
