using BitosX.Application.Abstractions.Persistence;
using BitosX.Application.Security;
using BitosX.Application.Verification;
using BitosX.Infrastructure.Persistence;
using Dapper;

namespace BitosX.Infrastructure.Tests;

/// <summary>Store-level account deletion: exact-hash re-check under lock, and cascade of every owned row.</summary>
[Collection("Persistence")]
public sealed class AccountDeletionStoreTests
{
    private readonly DatabaseFixture _fixture;
    private readonly AccountsTestContext _ctx;
    private readonly AccountDeletionStore _deletion;
    private readonly PasswordResetStore _resets;
    private readonly SessionStore _sessions;
    private readonly EnvelopeStore _envelopes;

    public AccountDeletionStoreTests(DatabaseFixture fixture)
    {
        _fixture = fixture;
        _ctx = new AccountsTestContext(fixture.ConnectionFactory);
        _deletion = new AccountDeletionStore(fixture.ConnectionFactory);
        _resets = new PasswordResetStore(fixture.ConnectionFactory, _ctx.Clock);
        _sessions = new SessionStore(fixture.ConnectionFactory, _ctx.Clock, new RefreshTokenOptions());
        _envelopes = new EnvelopeStore(fixture.ConnectionFactory, _ctx.Clock);
    }

    private async Task<long> CountAsync(string sql, object p)
    {
        await using var c = await _fixture.ConnectionFactory.OpenConnectionAsync();
        return await c.ExecuteScalarAsync<long>(new CommandDefinition(sql, p));
    }

    private async Task<(Guid AccountId, string Email, string Phc)> VerifiedAccountWithEverythingAsync(DateTime now)
    {
        var r = await _ctx.RegisterAsync(now);
        var phc = await _ctx.Hasher.HashAsync("Correct-Horse-Battery-Staple-1");
        Assert.Equal(VerificationOutcome.Verified, await _ctx.VerificationStore.FinalizeVerificationAsync(r.Verifier, phc));

        var login = await _sessions.CreateOnLoginAsync(new LoginSessionCreateRequest
        {
            AccountId = r.AccountId, NormalizedEmail = Application.Accounts.EmailNormalizer.Normalize(r.Email),
            ExpectedPasswordHash = phc, InitialRefreshVerifier = Enumerable.Repeat((byte)0x21, 32).ToArray(),
        });
        Assert.Equal(LoginSessionCreateOutcome.Created, login.Outcome);

        var reset = new VerificationChallengeFactory(_ctx.Tokens, _ctx.Protector, new EmailVerificationSecurityOptions { Pepper = "x" })
            .CreatePasswordReset(r.AccountId, r.Email, now);
        Assert.Equal(PasswordResetIssueOutcome.Issued, await _resets.IssueChallengeAsync(r.AccountId, reset.Challenge, reset.Outbox, now, TimeSpan.Zero));

        var envelope = "{\"version\":1,\"kdf\":\"argon2id\"}"u8.ToArray();
        var stored = await _envelopes.UpsertAsync(r.AccountId, 0, envelope, System.Security.Cryptography.SHA256.HashData(envelope));
        Assert.Equal(EnvelopeUpsertOutcome.Stored, stored.Outcome);

        return (r.AccountId, r.Email, phc);
    }

    [Fact]
    public async Task Delete_WithExactHash_RemovesAccountAndEveryOwnedRow()
    {
        await _fixture.ResetAsync();
        var now = AccountsTestContext.NowMicro();
        _ctx.Clock.SetUtcNow(now);
        var (accountId, _, phc) = await VerifiedAccountWithEverythingAsync(now);
        var p = new { a = accountId };

        Assert.Equal(2L, await CountAsync("SELECT COUNT(*) FROM email_verification_challenges WHERE account_id=@a", p));
        Assert.Equal(2L, await CountAsync("SELECT COUNT(*) FROM email_outbox o JOIN email_verification_challenges c ON c.id=o.challenge_id WHERE c.account_id=@a", p));
        Assert.Equal(1L, await CountAsync("SELECT COUNT(*) FROM sessions WHERE account_id=@a", p));
        Assert.Equal(1L, await CountAsync("SELECT COUNT(*) FROM refresh_tokens r JOIN sessions s ON s.id=r.session_id WHERE s.account_id=@a", p));
        Assert.Equal(1L, await CountAsync("SELECT COUNT(*) FROM vault_blobs WHERE account_id=@a", p));

        Assert.Equal(AccountDeleteOutcome.Deleted, await _deletion.DeleteAccountAsync(accountId, phc));

        Assert.Equal(0L, await CountAsync("SELECT COUNT(*) FROM accounts WHERE id=@a", p));
        Assert.Equal(0L, await CountAsync("SELECT COUNT(*) FROM email_verification_challenges WHERE account_id=@a", p));
        Assert.Equal(0L, await CountAsync("SELECT COUNT(*) FROM email_outbox o JOIN email_verification_challenges c ON c.id=o.challenge_id WHERE c.account_id=@a", p));
        Assert.Equal(0L, await CountAsync("SELECT COUNT(*) FROM sessions WHERE account_id=@a", p));
        Assert.Equal(0L, await CountAsync("SELECT COUNT(*) FROM vault_blobs WHERE account_id=@a", p));
        // Nothing dangling at all (all outbox rows belonged to this account's challenges).
        Assert.Equal(0L, await CountAsync("SELECT COUNT(*) FROM email_outbox", p));

        // Idempotent failure afterwards: the account is simply gone.
        Assert.Equal(AccountDeleteOutcome.InvalidAccountState, await _deletion.DeleteAccountAsync(accountId, phc));
    }

    [Fact]
    public async Task Delete_WithStaleHash_DoesNothing()
    {
        await _fixture.ResetAsync();
        var now = AccountsTestContext.NowMicro();
        _ctx.Clock.SetUtcNow(now);
        var (accountId, _, phc) = await VerifiedAccountWithEverythingAsync(now);

        // The password changed between the caller's Argon2 verify and the store call (e.g. a concurrent reset).
        var otherPhc = await _ctx.Hasher.HashAsync("Another-Strong-Password-22");
        Assert.NotEqual(phc, otherPhc);

        Assert.Equal(AccountDeleteOutcome.InvalidAccountState, await _deletion.DeleteAccountAsync(accountId, otherPhc));
        Assert.Equal(1L, await CountAsync("SELECT COUNT(*) FROM accounts WHERE id=@a", new { a = accountId }));
        Assert.Equal(1L, await CountAsync("SELECT COUNT(*) FROM vault_blobs WHERE account_id=@a", new { a = accountId }));
    }

    [Fact]
    public async Task Delete_UnverifiedAccount_Refused()
    {
        await _fixture.ResetAsync();
        var now = AccountsTestContext.NowMicro();
        var r = await _ctx.RegisterAsync(now);

        Assert.Equal(AccountDeleteOutcome.InvalidAccountState, await _deletion.DeleteAccountAsync(r.AccountId, "$argon2id$v=19$m=8192,t=1,p=1$c2FsdA$aGFzaA"));
        Assert.Equal(1L, await CountAsync("SELECT COUNT(*) FROM accounts WHERE id=@a", new { a = r.AccountId }));
    }
}
