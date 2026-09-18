using BitosX.Application.Abstractions.Persistence;
using BitosX.Application.Email;
using BitosX.Application.Verification;
using Dapper;

namespace BitosX.Infrastructure.Tests;

[Collection("Persistence")]
public sealed class DisabledAccountTests
{
    private readonly DatabaseFixture _fixture;
    private readonly AccountsTestContext _ctx;

    public DisabledAccountTests(DatabaseFixture fixture)
    {
        _fixture = fixture;
        _ctx = new AccountsTestContext(fixture.ConnectionFactory);
    }

    private async Task DisableAsync(Guid accountId, DateTime at)
    {
        await using var c = await _fixture.ConnectionFactory.OpenConnectionAsync();
        await c.ExecuteAsync(new CommandDefinition(
            "UPDATE accounts SET disabled_at=@at WHERE id=@id", new { at, id = accountId }));
    }

    private async Task<long> ScalarAsync(string sql, object p)
    {
        await using var c = await _fixture.ConnectionFactory.OpenConnectionAsync();
        return Convert.ToInt64(await c.ExecuteScalarAsync(new CommandDefinition(sql, p)));
    }

    [Fact]
    public async Task DisabledAccount_CannotVerify_RemainsUnchanged()
    {
        await _fixture.ResetAsync();
        var now = AccountsTestContext.NowMicro();
        var r = await _ctx.RegisterAsync(now);
        await DisableAsync(r.AccountId, now);

        // Pre-check finds nothing; finalize rejects.
        Assert.Null(await _ctx.VerificationStore.FindActiveChallengeByVerifierAsync(r.Verifier, now));
        _ctx.Clock.SetUtcNow(now);
        var outcome = await _ctx.VerificationStore.FinalizeVerificationAsync(r.Verifier, await _ctx.Hasher.HashAsync("pw-123456789012"));
        Assert.Equal(VerificationOutcome.InvalidOrExpired, outcome);

        // Account unchanged: still no password, not verified, still disabled; challenge not consumed.
        Assert.Equal(1, await ScalarAsync(
            "SELECT COUNT(*) FROM accounts WHERE id=@id AND password_hash IS NULL AND email_verified_at IS NULL AND disabled_at IS NOT NULL", new { id = r.AccountId }));
        Assert.Equal(1, await ScalarAsync(
            "SELECT COUNT(*) FROM email_verification_challenges WHERE id=@id AND consumed_at IS NULL", new { id = r.ChallengeId }));
    }

    [Fact]
    public async Task DisabledAccount_CannotResend()
    {
        await _fixture.ResetAsync();
        var now = AccountsTestContext.NowMicro();
        var r = await _ctx.RegisterAsync(now);
        await DisableAsync(r.AccountId, now);

        var later = now.AddMinutes(5);
        var token = _ctx.Tokens.GenerateToken();
        var newChallenge = new EmailVerificationChallenge { Id = Guid.NewGuid(), AccountId = r.AccountId, TokenHash = token.VerifierHash, CreatedAt = later, ExpiresAt = later.AddMinutes(30) };
        var outboxId = Guid.NewGuid();
        var payload = _ctx.Protector.Protect(new OutboxPayload(1, r.AccountId, token.TokenBase64Url, later.AddMinutes(30), r.Email),
            new OutboxAad(outboxId, 1, OutboxMessageTypes.EmailVerification, r.Email));
        var newOutbox = new EmailOutboxMessage(outboxId, newChallenge.Id, OutboxMessageTypes.EmailVerification, r.Email, payload, later, later);

        var outcome = await _ctx.VerificationStore.ReplaceActiveChallengeAsync(r.AccountId, newChallenge, newOutbox, later, TimeSpan.FromSeconds(60));

        Assert.Equal(ResendOutcome.AccountNotEligible, outcome);
        Assert.Equal(0, await ScalarAsync("SELECT COUNT(*) FROM email_verification_challenges WHERE id=@id", new { id = newChallenge.Id }));
    }
}
