using BitosX.Application.Abstractions.Persistence;
using BitosX.Application.Security;
using BitosX.Application.Verification;
using Dapper;
using Microsoft.Extensions.Time.Testing;

namespace BitosX.Infrastructure.Tests;

/// <summary>Hasher wrapper that advances a fake clock to simulate Argon2 duration.</summary>
internal sealed class AdvancingHasher : IAccountPasswordHasher
{
    private readonly IAccountPasswordHasher _inner;
    private readonly FakeTimeProvider _clock;
    private readonly TimeSpan _advance;
    public AdvancingHasher(IAccountPasswordHasher inner, FakeTimeProvider clock, TimeSpan advance)
    { _inner = inner; _clock = clock; _advance = advance; }
    public Task<string> HashAsync(string password, CancellationToken cancellationToken = default) { _clock.Advance(_advance); return _inner.HashAsync(password, cancellationToken); }
    public Task<PasswordVerificationResult> VerifyAsync(string password, string encoded, CancellationToken cancellationToken = default) => _inner.VerifyAsync(password, encoded, cancellationToken);
}

[Collection("Persistence")]
public sealed class VerificationExpiryRaceTests
{
    private readonly DatabaseFixture _fixture;
    private readonly AccountsTestContext _ctx;

    public VerificationExpiryRaceTests(DatabaseFixture fixture)
    {
        _fixture = fixture;
        _ctx = new AccountsTestContext(fixture.ConnectionFactory);
    }

    [Fact]
    public async Task TokenExpiringDuringHash_IsRejected_NoPartialActivation()
    {
        await _fixture.ResetAsync();
        var start = new DateTimeOffset(2026, 9, 16, 12, 0, 0, TimeSpan.Zero);
        _ctx.Clock.SetUtcNow(start.UtcDateTime); // store + service share this clock

        // Challenge expires 100ms after start.
        var r = await _ctx.RegisterAsync(start.UtcDateTime, ttl: TimeSpan.FromMilliseconds(100));

        // Hashing "takes" 200ms → the token expires during Phase B; the store reads its
        // authoritative time AFTER the lock and rejects it.
        var hasher = new AdvancingHasher(_ctx.Hasher, _ctx.Clock, TimeSpan.FromMilliseconds(200));
        var factory = new VerificationChallengeFactory(_ctx.Tokens, _ctx.Protector, new EmailVerificationSecurityOptions { Pepper = "x" });
        var service = new EmailVerificationService(
            new BitosX.Infrastructure.Persistence.AccountRepository(_fixture.ConnectionFactory),
            _ctx.VerificationStore, _ctx.Tokens, factory, hasher,
            new EmailVerificationSecurityOptions { Pepper = "x" }, _ctx.Clock);

        var result = await service.VerifyAsync(new VerifyEmailCommand(r.Token, "a-valid-password-123"));

        Assert.Equal(VerifyResult.Invalid, result);
        // No partial activation.
        Assert.Equal(1L, await ScalarAsync(
            "SELECT COUNT(*) FROM accounts WHERE id=@id AND password_hash IS NULL AND email_verified_at IS NULL", r.AccountId));
        Assert.Equal(1L, await ScalarAsync(
            "SELECT COUNT(*) FROM email_verification_challenges WHERE id=@id AND consumed_at IS NULL", r.ChallengeId));
    }

    [Fact]
    public async Task TokenStillValidAfterHash_Succeeds()
    {
        await _fixture.ResetAsync();
        var start = new DateTimeOffset(2026, 9, 16, 12, 0, 0, TimeSpan.Zero);
        _ctx.Clock.SetUtcNow(start.UtcDateTime);
        var r = await _ctx.RegisterAsync(start.UtcDateTime, ttl: TimeSpan.FromMinutes(30));

        var hasher = new AdvancingHasher(_ctx.Hasher, _ctx.Clock, TimeSpan.FromMilliseconds(200)); // well within TTL
        var factory = new VerificationChallengeFactory(_ctx.Tokens, _ctx.Protector, new EmailVerificationSecurityOptions { Pepper = "x" });
        var service = new EmailVerificationService(
            new BitosX.Infrastructure.Persistence.AccountRepository(_fixture.ConnectionFactory),
            _ctx.VerificationStore, _ctx.Tokens, factory, hasher,
            new EmailVerificationSecurityOptions { Pepper = "x" }, _ctx.Clock);

        var result = await service.VerifyAsync(new VerifyEmailCommand(r.Token, "a-valid-password-123"));
        Assert.Equal(VerifyResult.Verified, result);
    }

    [Fact]
    public async Task Finalize_ReadsAuthoritativeTimeAfterLock_RejectsIfExpiredMeanwhile()
    {
        // Direct store test of the "time advanced by the time the lock was acquired" case.
        await _fixture.ResetAsync();
        var start = new DateTimeOffset(2026, 9, 16, 12, 0, 0, TimeSpan.Zero);
        _ctx.Clock.SetUtcNow(start.UtcDateTime);
        var r = await _ctx.RegisterAsync(start.UtcDateTime, ttl: TimeSpan.FromMilliseconds(100));

        // As if the FOR UPDATE lock wait pushed the authoritative clock past expiry.
        _ctx.Clock.SetUtcNow(start.UtcDateTime.AddMilliseconds(200));

        var outcome = await _ctx.VerificationStore.FinalizeVerificationAsync(r.Verifier, await _ctx.Hasher.HashAsync("a-valid-password-123"));

        Assert.Equal(VerificationOutcome.InvalidOrExpired, outcome);
        Assert.Equal(1L, await ScalarAsync("SELECT COUNT(*) FROM accounts WHERE id=@id AND password_hash IS NULL AND email_verified_at IS NULL", r.AccountId));
        Assert.Equal(1L, await ScalarAsync("SELECT COUNT(*) FROM email_verification_challenges WHERE id=@id AND consumed_at IS NULL", r.ChallengeId));
    }

    private async Task<long> ScalarAsync(string sql, Guid id)
    {
        await using var c = await _fixture.ConnectionFactory.OpenConnectionAsync();
        return Convert.ToInt64(await c.ExecuteScalarAsync(new CommandDefinition(sql, new { id })));
    }
}
