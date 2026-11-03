using BitosX.Application.Abstractions.Persistence;
using BitosX.Application.Security;
using BitosX.Application.Verification;
using BitosX.Infrastructure.Persistence;
using Dapper;

namespace BitosX.Infrastructure.Tests;

/// <summary>
/// Password change while signed in, against the test DB: the exact verified hash is re-checked under the
/// account lock, every other session and its refresh tokens are revoked while the caller's survives, and
/// open password-reset links die with the old password.
/// </summary>
[Collection("Persistence")]
public sealed class AccountPasswordStoreTests
{
    private const string NewPhc = "$argon2id$v=19$m=8192,t=1,p=1$bmV3c2FsdG5ld3NhbHQ$bmV3aGFzaG5ld2hhc2huZXdoYXNobmV3aGFzaA";

    private readonly DatabaseFixture _fixture;
    private readonly AccountsTestContext _ctx;
    private readonly AccountPasswordStore _store;
    private readonly SessionStore _sessions;
    private readonly PasswordResetStore _resets;

    public AccountPasswordStoreTests(DatabaseFixture fixture)
    {
        _fixture = fixture;
        _ctx = new AccountsTestContext(fixture.ConnectionFactory);
        _store = new AccountPasswordStore(fixture.RuntimeConnectionFactory, _ctx.Clock);
        _sessions = new SessionStore(fixture.ConnectionFactory, _ctx.Clock, new RefreshTokenOptions());
        _resets = new PasswordResetStore(fixture.ConnectionFactory, _ctx.Clock);
    }

    private async Task<T> ScalarAsync<T>(string sql, object p)
    {
        await using var c = await _fixture.ConnectionFactory.OpenConnectionAsync();
        return (T)Convert.ChangeType(await c.ExecuteScalarAsync(new CommandDefinition(sql, p)) ?? 0L, typeof(T));
    }

    private async Task<(Guid AccountId, string Email, string Phc)> VerifiedAccountAsync(DateTime now)
    {
        var r = await _ctx.RegisterAsync(now);
        var phc = await _ctx.Hasher.HashAsync("Correct-Horse-Battery-Staple-1");
        Assert.Equal(VerificationOutcome.Verified, await _ctx.VerificationStore.FinalizeVerificationAsync(r.Verifier, phc));
        return (r.AccountId, r.Email, phc);
    }

    private async Task<Guid> OpenSessionAsync(Guid accountId, string email, string phc)
    {
        var result = await _sessions.CreateOnLoginAsync(new LoginSessionCreateRequest
        {
            AccountId = accountId, NormalizedEmail = Application.Accounts.EmailNormalizer.Normalize(email),
            ExpectedPasswordHash = phc, InitialRefreshVerifier = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32),
        });
        Assert.Equal(LoginSessionCreateOutcome.Created, result.Outcome);
        return result.SessionId;
    }

    [Fact]
    public async Task Change_ReplacesTheHash_RevokesOtherSessions_KeepsTheCaller_AndKillsResetLinks()
    {
        _ctx.Clock.SetUtcNow(new DateTimeOffset(AccountsTestContext.NowMicro()));
        var now = _ctx.Clock.GetUtcNow().UtcDateTime;
        var (accountId, email, phc) = await VerifiedAccountAsync(now);
        var caller = await OpenSessionAsync(accountId, email, phc);
        var other1 = await OpenSessionAsync(accountId, email, phc);
        var other2 = await OpenSessionAsync(accountId, email, phc);
        var reset = new VerificationChallengeFactory(_ctx.Tokens, _ctx.Protector, new EmailVerificationSecurityOptions { Pepper = "x" })
            .CreatePasswordReset(accountId, email, now);
        Assert.Equal(PasswordResetIssueOutcome.Issued, await _resets.IssueChallengeAsync(accountId, reset.Challenge, reset.Outbox, now, TimeSpan.Zero));

        var outcome = await _store.ChangePasswordAsync(accountId, caller, phc, NewPhc);

        Assert.Equal(PasswordChangeOutcome.Changed, outcome);
        Assert.Equal(NewPhc, await ScalarAsync<string>("SELECT password_hash FROM accounts WHERE id=@a", new { a = accountId }));
        Assert.Equal(0L, await ScalarAsync<long>("SELECT COUNT(*) FROM sessions WHERE id=@s AND revoked_at IS NOT NULL", new { s = caller }));
        Assert.Equal(0L, await ScalarAsync<long>("SELECT COUNT(*) FROM refresh_tokens WHERE session_id=@s AND revoked_at IS NOT NULL", new { s = caller }));
        foreach (var s in new[] { other1, other2 })
        {
            Assert.Equal(1L, await ScalarAsync<long>("SELECT COUNT(*) FROM sessions WHERE id=@s AND revoked_at IS NOT NULL", new { s }));
            Assert.Equal(0L, await ScalarAsync<long>("SELECT COUNT(*) FROM refresh_tokens WHERE session_id=@s AND revoked_at IS NULL", new { s }));
        }

        Assert.Equal(0L, await ScalarAsync<long>(
            "SELECT COUNT(*) FROM email_verification_challenges WHERE account_id=@a AND purpose='password_reset' AND invalidated_at IS NULL AND consumed_at IS NULL",
            new { a = accountId }));
        Assert.Null(await _resets.FindActiveChallengeByVerifierAsync(reset.Challenge.TokenHash, now));
    }

    [Fact]
    public async Task Change_WithAHashThatDiffersOnlyInLetterCase_IsRefused()
    {
        var now = AccountsTestContext.NowMicro();
        var (accountId, email, phc) = await VerifiedAccountAsync(now);
        var caller = await OpenSessionAsync(accountId, email, phc);

        // The PHC salt/hash are case-sensitive Base64: an "equal ignoring case" hash is a different credential.
        var outcome = await _store.ChangePasswordAsync(accountId, caller, phc.ToUpperInvariant(), NewPhc);

        Assert.Equal(PasswordChangeOutcome.InvalidAccountState, outcome);
        Assert.Equal(phc, await ScalarAsync<string>("SELECT password_hash FROM accounts WHERE id=@a", new { a = accountId }));
    }

    [Fact]
    public async Task Change_DisabledOrUnknownAccount_IsRefused_AndRevokesNothing()
    {
        var now = AccountsTestContext.NowMicro();
        var (accountId, email, phc) = await VerifiedAccountAsync(now);
        var caller = await OpenSessionAsync(accountId, email, phc);
        var other = await OpenSessionAsync(accountId, email, phc);
        await using (var c = await _fixture.ConnectionFactory.OpenConnectionAsync())
        {
            await c.ExecuteAsync("UPDATE accounts SET disabled_at=@now WHERE id=@accountId", new { now, accountId });
        }

        Assert.Equal(PasswordChangeOutcome.InvalidAccountState, await _store.ChangePasswordAsync(accountId, caller, phc, NewPhc));
        Assert.Equal(PasswordChangeOutcome.InvalidAccountState, await _store.ChangePasswordAsync(Guid.NewGuid(), caller, phc, NewPhc));
        Assert.Equal(0L, await ScalarAsync<long>("SELECT COUNT(*) FROM sessions WHERE id=@s AND revoked_at IS NOT NULL", new { s = other }));
    }
}
