using System.Security.Cryptography;
using BitosX.Application.Abstractions.Persistence;
using BitosX.Application.Mfa;
using BitosX.Infrastructure.Persistence;
using Dapper;

namespace BitosX.Infrastructure.Tests;

[Collection("Persistence")]
public sealed class TotpStoreTests
{
    private readonly DatabaseFixture _fixture;
    private readonly AccountsTestContext _ctx;
    private readonly TotpStore _store;
    private readonly MfaChallengeStore _challenges;

    public TotpStoreTests(DatabaseFixture fixture)
    {
        _fixture = fixture;
        _ctx = new AccountsTestContext(fixture.ConnectionFactory);
        _store = new TotpStore(fixture.ConnectionFactory);
        _challenges = new MfaChallengeStore(fixture.ConnectionFactory);
    }

    private static ProtectedTotpSecret Secret() => new(1, RandomNumberGenerator.GetBytes(12), RandomNumberGenerator.GetBytes(20), RandomNumberGenerator.GetBytes(16));
    private static List<byte[]> Verifiers(int n) => Enumerable.Range(0, n).Select(_ => RandomNumberGenerator.GetBytes(32)).ToList();

    private async Task<long> CountAsync(string sql, object p)
    {
        await using var c = await _fixture.ConnectionFactory.OpenConnectionAsync();
        return await c.ExecuteScalarAsync<long>(new CommandDefinition(sql, p));
    }

    [Fact]
    public async Task Pending_Confirm_Replay_Recovery_Disable_Lifecycle()
    {
        await _fixture.ResetAsync();
        var now = AccountsTestContext.NowMicro();
        var r = await _ctx.RegisterAsync(now);
        var a = r.AccountId;

        Assert.Null(await _store.GetAsync(a));

        // Pending can be replaced; a confirmed row cannot.
        Assert.Equal(TotpPendingOutcome.Stored, await _store.StorePendingAsync(a, Secret(), now));
        var second = Secret();
        Assert.Equal(TotpPendingOutcome.Stored, await _store.StorePendingAsync(a, second, now));
        var pending = await _store.GetAsync(a);
        Assert.False(pending!.IsConfirmed);
        Assert.Equal(second.Ciphertext, pending.Secret.Ciphertext);

        // Replay guard and recovery codes do nothing while pending.
        Assert.False(await _store.TryConsumeStepAsync(a, 100));
        Assert.False(await _store.ReplaceRecoveryCodesAsync(a, Verifiers(3), now));

        var codes = Verifiers(10);
        Assert.Equal(TotpConfirmOutcome.Confirmed, await _store.ConfirmAsync(a, 100, codes, now));
        Assert.Equal(TotpConfirmOutcome.NotPending, await _store.ConfirmAsync(a, 101, Verifiers(10), now));
        Assert.Equal(TotpPendingOutcome.AlreadyConfirmed, await _store.StorePendingAsync(a, Secret(), now));
        var confirmed = await _store.GetAsync(a);
        Assert.True(confirmed!.IsConfirmed);
        Assert.Equal(100, confirmed.LastUsedStep);
        Assert.Equal(10, await _store.CountUnusedRecoveryCodesAsync(a));

        // Steps: only strictly newer than the last used one, each once.
        Assert.False(await _store.TryConsumeStepAsync(a, 100));
        Assert.False(await _store.TryConsumeStepAsync(a, 99));
        Assert.True(await _store.TryConsumeStepAsync(a, 101));
        Assert.False(await _store.TryConsumeStepAsync(a, 101));
        Assert.Equal(101, (await _store.GetAsync(a))!.LastUsedStep);

        // Recovery codes: single use, account-bound.
        Assert.True(await _store.TryConsumeRecoveryCodeAsync(a, codes[0], now));
        Assert.False(await _store.TryConsumeRecoveryCodeAsync(a, codes[0], now));
        Assert.False(await _store.TryConsumeRecoveryCodeAsync(Guid.NewGuid(), codes[1], now));
        Assert.Equal(9, await _store.CountUnusedRecoveryCodesAsync(a));

        var replacement = Verifiers(10);
        Assert.True(await _store.ReplaceRecoveryCodesAsync(a, replacement, now));
        Assert.Equal(10, await _store.CountUnusedRecoveryCodesAsync(a));
        Assert.False(await _store.TryConsumeRecoveryCodeAsync(a, codes[2], now)); // old set is gone

        // An open challenge dies with the enrollment.
        await _challenges.CreateAsync(new MfaChallenge(Guid.NewGuid(), a, RandomNumberGenerator.GetBytes(32), RandomNumberGenerator.GetBytes(32), null, now, now.AddMinutes(5)));
        await _store.DisableAsync(a);
        Assert.Null(await _store.GetAsync(a));
        Assert.Equal(0L, await CountAsync("SELECT COUNT(*) FROM account_recovery_codes WHERE account_id=@a", new { a }));
        Assert.Equal(0L, await CountAsync("SELECT COUNT(*) FROM mfa_challenges WHERE account_id=@a", new { a }));
    }

    [Fact]
    public async Task ReservingAttempts_UnderConcurrency_NeverExceedsTheLimit()
    {
        var now = AccountsTestContext.NowMicro();
        var r = await _ctx.RegisterAsync(now);
        var id = Guid.NewGuid();
        await _challenges.CreateAsync(new MfaChallenge(id, r.AccountId, RandomNumberGenerator.GetBytes(32), RandomNumberGenerator.GetBytes(32), null, now, now.AddMinutes(5)));

        // 40 requests race for one challenge: exactly 5 may ever check a code.
        var store = new MfaChallengeStore(_fixture.RuntimeConnectionFactory);
        var granted = await Task.WhenAll(Enumerable.Range(0, 40).Select(_ => Task.Run(() => store.TryReserveAttemptAsync(id, 5, now))));

        Assert.Equal(5, granted.Count(g => g));
        Assert.Equal(5L, await CountAsync("SELECT attempt_count FROM mfa_challenges WHERE id=@id", new { id }));
    }

    [Fact]
    public async Task ReservingAnAttempt_OnAnExpiredOrConsumedChallenge_Fails()
    {
        var now = AccountsTestContext.NowMicro();
        var r = await _ctx.RegisterAsync(now);
        var expired = Guid.NewGuid();
        await _challenges.CreateAsync(new MfaChallenge(expired, r.AccountId, RandomNumberGenerator.GetBytes(32), RandomNumberGenerator.GetBytes(32), null, now, now.AddMinutes(5)));
        Assert.False(await _challenges.TryReserveAttemptAsync(expired, 5, now.AddMinutes(6)));

        var consumed = Guid.NewGuid();
        await _challenges.CreateAsync(new MfaChallenge(consumed, r.AccountId, RandomNumberGenerator.GetBytes(32), RandomNumberGenerator.GetBytes(32), null, now, now.AddMinutes(5)));
        Assert.True(await _challenges.TryConsumeAsync(consumed, now));
        Assert.False(await _challenges.TryReserveAttemptAsync(consumed, 5, now));
    }

    [Fact]
    public async Task HasUnusedRecoveryCode_ReadsWithoutConsuming()
    {
        var now = AccountsTestContext.NowMicro();
        var r = await _ctx.RegisterAsync(now);
        var codes = Verifiers(5);
        Assert.Equal(TotpPendingOutcome.Stored, await _store.StorePendingAsync(r.AccountId, Secret(), now));
        Assert.Equal(TotpConfirmOutcome.Confirmed, await _store.ConfirmAsync(r.AccountId, 1, codes, now));

        Assert.True(await _store.HasUnusedRecoveryCodeAsync(r.AccountId, codes[0]));
        Assert.True(await _store.HasUnusedRecoveryCodeAsync(r.AccountId, codes[0]));
        Assert.False(await _store.HasUnusedRecoveryCodeAsync(Guid.NewGuid(), codes[0]));
        Assert.True(await _store.TryConsumeRecoveryCodeAsync(r.AccountId, codes[0], now));
        Assert.False(await _store.HasUnusedRecoveryCodeAsync(r.AccountId, codes[0]));
    }

    [Fact]
    public async Task DeletingTheAccount_CascadesEverything()
    {
        await _fixture.ResetAsync();
        var now = AccountsTestContext.NowMicro();
        var r = await _ctx.RegisterAsync(now);
        Assert.Equal(TotpPendingOutcome.Stored, await _store.StorePendingAsync(r.AccountId, Secret(), now));
        Assert.Equal(TotpConfirmOutcome.Confirmed, await _store.ConfirmAsync(r.AccountId, 1, Verifiers(5), now));
        await _challenges.CreateAsync(new MfaChallenge(Guid.NewGuid(), r.AccountId, RandomNumberGenerator.GetBytes(32), RandomNumberGenerator.GetBytes(32), "ua", now, now.AddMinutes(5)));

        await using (var c = await _fixture.ConnectionFactory.OpenConnectionAsync())
        {
            await c.ExecuteAsync("DELETE FROM accounts WHERE id=@id", new { id = r.AccountId });
        }

        Assert.Equal(0L, await CountAsync("SELECT COUNT(*) FROM account_totp", new { }));
        Assert.Equal(0L, await CountAsync("SELECT COUNT(*) FROM account_recovery_codes", new { }));
        Assert.Equal(0L, await CountAsync("SELECT COUNT(*) FROM mfa_challenges", new { }));
    }

    [Fact]
    public async Task Challenge_FindConsume_Attempts_Expiry()
    {
        await _fixture.ResetAsync();
        var now = AccountsTestContext.NowMicro();
        var r = await _ctx.RegisterAsync(now);
        var verifier = RandomNumberGenerator.GetBytes(32);
        var fingerprint = RandomNumberGenerator.GetBytes(32);
        var id = Guid.NewGuid();
        await _challenges.CreateAsync(new MfaChallenge(id, r.AccountId, verifier, fingerprint, "Agent/1", now, now.AddMinutes(5)));

        var found = await _challenges.FindActiveAsync(verifier, now);
        Assert.NotNull(found);
        Assert.Equal(r.AccountId, found!.AccountId);
        Assert.Equal(fingerprint, found.PasswordHashFingerprint);
        Assert.Equal("Agent/1", found.UserAgent);
        Assert.Equal(0, found.AttemptCount);
        Assert.Null(await _challenges.FindActiveAsync(RandomNumberGenerator.GetBytes(32), now));
        Assert.True(await _challenges.FindActiveAsync(verifier, now.AddMinutes(6)) is null, "expired");

        // Failed attempts: each is reserved first; after the fifth the challenge is closed.
        for (var i = 0; i < 4; i++)
        {
            Assert.True(await _challenges.TryReserveAttemptAsync(id, 5, now));
            await _challenges.CloseIfAttemptsExhaustedAsync(id, 5, now);
        }

        Assert.Equal(4, (await _challenges.FindActiveAsync(verifier, now))!.AttemptCount);
        Assert.True(await _challenges.TryReserveAttemptAsync(id, 5, now));
        await _challenges.CloseIfAttemptsExhaustedAsync(id, 5, now);
        Assert.Null(await _challenges.FindActiveAsync(verifier, now));
        Assert.False(await _challenges.TryReserveAttemptAsync(id, 5, now));
        Assert.False(await _challenges.TryConsumeAsync(id, now));

        // A fresh one is single use.
        var verifier2 = RandomNumberGenerator.GetBytes(32);
        var id2 = Guid.NewGuid();
        await _challenges.CreateAsync(new MfaChallenge(id2, r.AccountId, verifier2, fingerprint, null, now, now.AddMinutes(5)));
        Assert.True(await _challenges.TryConsumeAsync(id2, now));
        Assert.False(await _challenges.TryConsumeAsync(id2, now));
        Assert.Null(await _challenges.FindActiveAsync(verifier2, now));
    }
}
