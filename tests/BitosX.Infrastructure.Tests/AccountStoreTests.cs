using BitosX.Application.Abstractions.Persistence;
using BitosX.Application.Accounts;
using BitosX.Application.Email;
using BitosX.Application.Verification;
using Dapper;

namespace BitosX.Infrastructure.Tests;

[Collection("Persistence")]
public sealed class AccountStoreTests
{
    private readonly DatabaseFixture _fixture;
    private readonly AccountsTestContext _ctx;

    public AccountStoreTests(DatabaseFixture fixture)
    {
        _fixture = fixture;
        _ctx = new AccountsTestContext(fixture.ConnectionFactory);
    }

    private async Task<long> ScalarAsync(string sql, object p)
    {
        await using var c = await _fixture.ConnectionFactory.OpenConnectionAsync();
        return Convert.ToInt64(await c.ExecuteScalarAsync(new CommandDefinition(sql, p)));
    }

    private async Task<string?> PasswordHashAsync(Guid id)
    {
        await using var c = await _fixture.ConnectionFactory.OpenConnectionAsync();
        return await c.ExecuteScalarAsync<string?>(new CommandDefinition(
            "SELECT password_hash FROM accounts WHERE id=@id", new { id }));
    }

    // ---- registration store ----

    [Fact]
    public async Task Register_CreatesAccountChallengeAndOutbox_WithNullPassword()
    {
        await _fixture.ResetAsync();
        var now = AccountsTestContext.NowMicro();
        var r = await _ctx.RegisterAsync(now);

        Assert.Null(await PasswordHashAsync(r.AccountId));
        Assert.Equal(1, await ScalarAsync("SELECT COUNT(*) FROM accounts WHERE id=@id AND email_verified_at IS NULL", new { id = r.AccountId }));
        Assert.Equal(1, await ScalarAsync("SELECT COUNT(*) FROM email_verification_challenges WHERE id=@id", new { id = r.ChallengeId }));
        Assert.Equal(1, await ScalarAsync("SELECT COUNT(*) FROM email_outbox WHERE id=@id", new { id = r.OutboxId }));
    }

    [Fact]
    public async Task Register_DuplicateNormalizedEmail_ReturnsExists_NoPartialRows()
    {
        await _fixture.ResetAsync();
        var now = AccountsTestContext.NowMicro();
        var first = await _ctx.RegisterAsync(now);

        // Second account, same normalized email, distinct ids.
        var dupAccount = new Account
        {
            Id = Guid.NewGuid(), Email = first.Email, NormalizedEmail = EmailNormalizer.Normalize(first.Email),
            CreatedAt = now, UpdatedAt = now,
        };
        var token = _ctx.Tokens.GenerateToken();
        var challengeId = Guid.NewGuid();
        var outboxId = Guid.NewGuid();
        var challenge = new EmailVerificationChallenge { Id = challengeId, AccountId = dupAccount.Id, TokenHash = token.VerifierHash, CreatedAt = now, ExpiresAt = now.AddMinutes(30) };
        var payload = _ctx.Protector.Protect(new OutboxPayload(1, dupAccount.Id, token.TokenBase64Url, now.AddMinutes(30), first.Email),
            new OutboxAad(outboxId, 1, OutboxMessageTypes.EmailVerification, first.Email));
        var outbox = new EmailOutboxMessage(outboxId, challengeId, OutboxMessageTypes.EmailVerification, first.Email, payload, now, now);

        var outcome = await _ctx.RegistrationStore.CreateUnverifiedAccountWithChallengeAndOutboxAsync(dupAccount, challenge, outbox);

        Assert.Equal(RegistrationOutcome.EmailAlreadyExists, outcome);
        Assert.Equal(0, await ScalarAsync("SELECT COUNT(*) FROM accounts WHERE id=@id", new { id = dupAccount.Id }));
        Assert.Equal(0, await ScalarAsync("SELECT COUNT(*) FROM email_verification_challenges WHERE id=@id", new { id = challengeId }));
        Assert.Equal(0, await ScalarAsync("SELECT COUNT(*) FROM email_outbox WHERE id=@id", new { id = outboxId }));
    }

    // ---- verification store ----

    [Fact]
    public async Task Find_And_Finalize_SetsPasswordVerifiedConsumed_Atomically()
    {
        await _fixture.ResetAsync();
        var now = AccountsTestContext.NowMicro();
        var r = await _ctx.RegisterAsync(now);

        var view = await _ctx.VerificationStore.FindActiveChallengeByVerifierAsync(r.Verifier, now);
        Assert.NotNull(view);
        Assert.Equal(r.ChallengeId, view!.ChallengeId);

        var phc = _ctx.Hasher.Hash("my-chosen-password");
        _ctx.Clock.SetUtcNow(now);
        var outcome = await _ctx.VerificationStore.FinalizeVerificationAsync(r.Verifier, phc);
        Assert.Equal(VerificationOutcome.Verified, outcome);

        Assert.Equal(1, await ScalarAsync("SELECT COUNT(*) FROM accounts WHERE id=@id AND email_verified_at IS NOT NULL AND password_hash IS NOT NULL", new { id = r.AccountId }));
        Assert.Equal(1, await ScalarAsync("SELECT COUNT(*) FROM email_verification_challenges WHERE id=@id AND consumed_at IS NOT NULL", new { id = r.ChallengeId }));

        var storedHash = await PasswordHashAsync(r.AccountId);
        Assert.Equal(BitosX.Application.Security.PasswordVerificationResult.Success, _ctx.Hasher.Verify("my-chosen-password", storedHash!));
    }

    [Fact]
    public async Task Finalize_Twice_OnlyFirstSucceeds()
    {
        await _fixture.ResetAsync();
        var now = AccountsTestContext.NowMicro();
        var r = await _ctx.RegisterAsync(now);
        var phc = _ctx.Hasher.Hash("pw-123456789012");
        _ctx.Clock.SetUtcNow(now);

        Assert.Equal(VerificationOutcome.Verified, await _ctx.VerificationStore.FinalizeVerificationAsync(r.Verifier, phc));
        Assert.Equal(VerificationOutcome.InvalidOrExpired, await _ctx.VerificationStore.FinalizeVerificationAsync(r.Verifier, phc));
    }

    [Fact]
    public async Task Finalize_ExpiredChallenge_IsInvalid_AccountStaysNull()
    {
        await _fixture.ResetAsync();
        var now = AccountsTestContext.NowMicro();
        var r = await _ctx.RegisterAsync(now, ttl: TimeSpan.FromMinutes(30));
        var afterExpiry = now.AddMinutes(31);

        Assert.Null(await _ctx.VerificationStore.FindActiveChallengeByVerifierAsync(r.Verifier, afterExpiry));
        // Store reads authoritative time from its clock (set past expiry).
        _ctx.Clock.SetUtcNow(afterExpiry);
        var outcome = await _ctx.VerificationStore.FinalizeVerificationAsync(r.Verifier, _ctx.Hasher.Hash("pw-123456789012"));
        Assert.Equal(VerificationOutcome.InvalidOrExpired, outcome);
        Assert.Null(await PasswordHashAsync(r.AccountId));
    }

    [Fact]
    public async Task Replace_InvalidatesPrior_And_KeepsOneActive()
    {
        await _fixture.ResetAsync();
        var now = AccountsTestContext.NowMicro();
        var r = await _ctx.RegisterAsync(now);

        var later = now.AddMinutes(5);
        var token = _ctx.Tokens.GenerateToken();
        var newChallengeId = Guid.NewGuid();
        var newOutboxId = Guid.NewGuid();
        var newChallenge = new EmailVerificationChallenge { Id = newChallengeId, AccountId = r.AccountId, TokenHash = token.VerifierHash, CreatedAt = later, ExpiresAt = later.AddMinutes(30) };
        var payload = _ctx.Protector.Protect(new OutboxPayload(1, r.AccountId, token.TokenBase64Url, later.AddMinutes(30), r.Email),
            new OutboxAad(newOutboxId, 1, OutboxMessageTypes.EmailVerification, r.Email));
        var newOutbox = new EmailOutboxMessage(newOutboxId, newChallengeId, OutboxMessageTypes.EmailVerification, r.Email, payload, later, later);

        var outcome = await _ctx.VerificationStore.ReplaceActiveChallengeAsync(r.AccountId, newChallenge, newOutbox, later, TimeSpan.FromSeconds(60));
        Assert.Equal(ResendOutcome.Replaced, outcome);

        Assert.Equal(1, await ScalarAsync("SELECT COUNT(*) FROM email_verification_challenges WHERE id=@id AND invalidated_at IS NOT NULL AND consumed_at IS NULL", new { id = r.ChallengeId }));
        Assert.Equal(1, await ScalarAsync("SELECT COUNT(*) FROM email_verification_challenges WHERE account_id=@a AND consumed_at IS NULL AND invalidated_at IS NULL AND expires_at > @now", new { a = r.AccountId, now = later }));
    }

    [Fact]
    public async Task Replace_WithinMinInterval_SkipsTooSoon()
    {
        await _fixture.ResetAsync();
        var now = AccountsTestContext.NowMicro();
        var r = await _ctx.RegisterAsync(now);

        var token = _ctx.Tokens.GenerateToken();
        var newChallenge = new EmailVerificationChallenge { Id = Guid.NewGuid(), AccountId = r.AccountId, TokenHash = token.VerifierHash, CreatedAt = now, ExpiresAt = now.AddMinutes(30) };
        var outboxId = Guid.NewGuid();
        var payload = _ctx.Protector.Protect(new OutboxPayload(1, r.AccountId, token.TokenBase64Url, now.AddMinutes(30), r.Email),
            new OutboxAad(outboxId, 1, OutboxMessageTypes.EmailVerification, r.Email));
        var newOutbox = new EmailOutboxMessage(outboxId, newChallenge.Id, OutboxMessageTypes.EmailVerification, r.Email, payload, now, now);

        // The just-created challenge is younger than 60s → SkippedTooSoon.
        var outcome = await _ctx.VerificationStore.ReplaceActiveChallengeAsync(r.AccountId, newChallenge, newOutbox, now, TimeSpan.FromSeconds(60));
        Assert.Equal(ResendOutcome.SkippedTooSoon, outcome);
        Assert.Equal(0, await ScalarAsync("SELECT COUNT(*) FROM email_verification_challenges WHERE id=@id", new { id = newChallenge.Id }));
    }
}
