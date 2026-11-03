using System.Security.Cryptography;
using BitosX.Application.Abstractions.Persistence;
using BitosX.Application.Security;
using BitosX.Application.Sessions;
using BitosX.Infrastructure.Persistence;
using Dapper;
using Microsoft.Extensions.Time.Testing;

namespace BitosX.Infrastructure.Tests;

/// <summary>
/// Real-MariaDB tests for logout / logout-all / delete-session / list persistence, plus refresh-vs-
/// revocation concurrency and per-request auth integration. Store runs on the runtime DML connection.
/// </summary>
[Collection("Persistence")]
public sealed class SessionRevocationTests
{
    private static readonly DateTime Now = new(2026, 9, 18, 12, 0, 0, DateTimeKind.Utc);
    private const string Phc = "$argon2id$v=19$m=8192,t=1,p=1$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYQ";

    private readonly DatabaseFixture _fixture;
    public SessionRevocationTests(DatabaseFixture fixture) => _fixture = fixture;

    private static FakeTimeProvider Clock(DateTime? at = null) => new(new DateTimeOffset(at ?? Now, TimeSpan.Zero));
    private SessionStore Store(TimeProvider? clock = null) => new(_fixture.RuntimeConnectionFactory, clock ?? Clock(), new RefreshTokenOptions());
    private static byte[] NewVerifier() => RandomNumberGenerator.GetBytes(32);

    private async Task<Guid> SeedAccountAsync(bool disabled = false)
    {
        var id = Guid.NewGuid();
        var email = $"user-{id:N}@example.com";
        await using var c = await _fixture.ConnectionFactory.OpenConnectionAsync();
        await c.ExecuteAsync(
            """
            INSERT INTO accounts (id, email, normalized_email, email_verified_at, phone_e164, phone_verified_at,
                                  password_hash, created_at, updated_at, disabled_at)
            VALUES (@id, @email, @email, @now, NULL, NULL, @phc, @now, @now, @disabledAt);
            """, new { id, email, now = Now, phc = Phc, disabledAt = disabled ? Now : (DateTime?)null });
        return id;
    }

    private async Task<(Guid sessionId, Guid refreshTokenId)> SeedSessionTokenAsync(
        Guid accountId, byte[] tokenHash, DateTime? createdAt = null, DateTime? lastSeenAt = null,
        DateTime? absoluteExpiresAt = null, DateTime? sessionRevokedAt = null, DateTime? tokenRevokedAt = null)
    {
        var sessionId = Guid.NewGuid();
        var refreshTokenId = Guid.NewGuid();
        await using var c = await _fixture.ConnectionFactory.OpenConnectionAsync();
        await c.ExecuteAsync(
            """
            INSERT INTO sessions (id, account_id, created_at, last_seen_at, absolute_expires_at, revoked_at, user_agent)
            VALUES (@sessionId, @accountId, @createdAt, @lastSeen, @absolute, @sessionRevoked, 'ua');
            """, new { sessionId, accountId, createdAt = createdAt ?? Now, lastSeen = lastSeenAt ?? Now, absolute = absoluteExpiresAt ?? Now.AddDays(90), sessionRevoked = sessionRevokedAt });
        await c.ExecuteAsync(
            """
            INSERT INTO refresh_tokens (id, session_id, token_hash, created_at, expires_at, consumed_at, revoked_at, replaced_by_token_id)
            VALUES (@refreshTokenId, @sessionId, @tokenHash, @now, @expires, NULL, @tokenRevoked, NULL);
            """, new { refreshTokenId, sessionId, tokenHash, now = Now, expires = Now.AddDays(30), tokenRevoked = tokenRevokedAt });
        return (sessionId, refreshTokenId);
    }

    private async Task<T> ScalarAsync<T>(string sql, object p)
    {
        await using var c = await _fixture.ConnectionFactory.OpenConnectionAsync();
        return (await c.ExecuteScalarAsync<T>(sql, p))!;
    }

    private Task<DateTime?> SessionRevokedAtAsync(Guid id) => ScalarAsync<DateTime?>("SELECT revoked_at FROM sessions WHERE id=@id;", new { id });
    private Task<DateTime?> RefreshRevokedAtAsync(Guid id) => ScalarAsync<DateTime?>("SELECT revoked_at FROM refresh_tokens WHERE id=@id;", new { id });
    private Task<int> ActiveRefreshCountAsync(Guid sessionId) => ScalarAsync<int>("SELECT COUNT(*) FROM refresh_tokens WHERE session_id=@sid AND revoked_at IS NULL;", new { sid = sessionId });
    private Task<int> SessionCountAsync(Guid accountId) => ScalarAsync<int>("SELECT COUNT(*) FROM sessions WHERE account_id=@aid;", new { aid = accountId });
    private static async Task DisableAsync(DatabaseFixture f, Guid accountId, DateTime at)
    {
        await using var c = await f.ConnectionFactory.OpenConnectionAsync();
        await c.ExecuteAsync("UPDATE accounts SET disabled_at=@at WHERE id=@id;", new { at, id = accountId });
    }

    // ============================ LOGOUT ============================

    [Fact]
    public async Task Logout_ActiveSession_RevokesSessionAndRefresh_AtAuthoritativeNow()
    {
        var accountId = await SeedAccountAsync();
        var (sessionId, r0) = await SeedSessionTokenAsync(accountId, NewVerifier());
        var otherAccount = await SeedAccountAsync();
        var (otherAcctSession, _) = await SeedSessionTokenAsync(otherAccount, NewVerifier());
        var (sameAcctOtherSession, sameOtherToken) = await SeedSessionTokenAsync(accountId, NewVerifier());

        await Store().LogoutAsync(accountId, sessionId);

        Assert.Equal(Now, await SessionRevokedAtAsync(sessionId));
        Assert.Equal(Now, await RefreshRevokedAtAsync(r0));
        Assert.Null(await SessionRevokedAtAsync(otherAcctSession));      // other account untouched
        Assert.Null(await SessionRevokedAtAsync(sameAcctOtherSession));  // other same-account session untouched
        Assert.Equal(1, await ActiveRefreshCountAsync(sameAcctOtherSession));
    }

    [Fact]
    public async Task Logout_AlreadyRevoked_IdempotentSuccess()
    {
        var accountId = await SeedAccountAsync();
        var (sessionId, _) = await SeedSessionTokenAsync(accountId, NewVerifier(), sessionRevokedAt: Now.AddMinutes(-10), tokenRevokedAt: Now.AddMinutes(-10));
        await Store().LogoutAsync(accountId, sessionId); // no throw
        Assert.NotNull(await SessionRevokedAtAsync(sessionId));
    }

    [Fact]
    public async Task Logout_MissingSession_IdempotentSuccess()
        => await Store().LogoutAsync(await SeedAccountAsync(), Guid.NewGuid()); // no throw

    // ============================ LOGOUT-ALL ============================

    [Fact]
    public async Task LogoutAll_RevokesAllAccountSessionsAndTokens_OtherAccountUntouched_NoDeletes()
    {
        var accountId = await SeedAccountAsync();
        var s = new List<(Guid sid, Guid rid)>();
        for (var i = 0; i < 3; i++) s.Add(await SeedSessionTokenAsync(accountId, NewVerifier()));
        var otherAccount = await SeedAccountAsync();
        var (otherSession, otherToken) = await SeedSessionTokenAsync(otherAccount, NewVerifier());

        await Store().LogoutAllAsync(accountId);

        foreach (var (sid, rid) in s)
        {
            Assert.Equal(Now, await SessionRevokedAtAsync(sid));
            Assert.Equal(Now, await RefreshRevokedAtAsync(rid));
        }
        Assert.Null(await SessionRevokedAtAsync(otherSession));   // other account untouched
        Assert.Null(await RefreshRevokedAtAsync(otherToken));
        Assert.Equal(3, await SessionCountAsync(accountId));      // no rows deleted
    }

    [Fact]
    public async Task LogoutAll_AlreadyRevoked_Safe()
    {
        var accountId = await SeedAccountAsync();
        await SeedSessionTokenAsync(accountId, NewVerifier(), sessionRevokedAt: Now.AddMinutes(-10));
        await Store().LogoutAllAsync(accountId); // no throw
    }

    [Fact]
    public async Task LogoutAll_TwoConcurrent_SameAccount_CompleteSafely()
    {
        var accountId = await SeedAccountAsync();
        for (var i = 0; i < 3; i++) await SeedSessionTokenAsync(accountId, NewVerifier());
        var t1 = Store().LogoutAllAsync(accountId);
        var t2 = Store().LogoutAllAsync(accountId);
        await Task.WhenAll(t1, t2); // no deadlock, both idempotent
        Assert.Equal(0, await ScalarAsync<int>("SELECT COUNT(*) FROM sessions WHERE account_id=@aid AND revoked_at IS NULL;", new { aid = accountId }));
    }

    // ============================ DELETE SESSION ============================

    [Fact]
    public async Task Delete_OwnedTarget_Revoked()
    {
        var accountId = await SeedAccountAsync();
        var (sessionId, r0) = await SeedSessionTokenAsync(accountId, NewVerifier());
        var outcome = await Store().DeleteSessionAsync(accountId, sessionId);
        Assert.Equal(SessionDeleteOutcome.Deleted, outcome);
        Assert.Equal(Now, await SessionRevokedAtAsync(sessionId));
        Assert.Equal(Now, await RefreshRevokedAtAsync(r0));
    }

    [Fact]
    public async Task Delete_OwnedAlreadyRevoked_Idempotent_Deleted()
    {
        var accountId = await SeedAccountAsync();
        var (sessionId, _) = await SeedSessionTokenAsync(accountId, NewVerifier(), sessionRevokedAt: Now.AddMinutes(-5));
        Assert.Equal(SessionDeleteOutcome.Deleted, await Store().DeleteSessionAsync(accountId, sessionId));
    }

    [Fact]
    public async Task Delete_Nonexistent_NotFound()
        => Assert.Equal(SessionDeleteOutcome.NotFound, await Store().DeleteSessionAsync(await SeedAccountAsync(), Guid.NewGuid()));

    [Fact]
    public async Task Delete_OtherAccountsSession_NotFound_AndUntouched()
    {
        var accountId = await SeedAccountAsync();
        var otherAccount = await SeedAccountAsync();
        var (otherSession, _) = await SeedSessionTokenAsync(otherAccount, NewVerifier());
        Assert.Equal(SessionDeleteOutcome.NotFound, await Store().DeleteSessionAsync(accountId, otherSession));
        Assert.Null(await SessionRevokedAtAsync(otherSession)); // untouched
    }

    // ============================ LIST ============================

    [Fact]
    public async Task List_OnlyAccountUnrevokedSessions_DeterministicOrder()
    {
        var accountId = await SeedAccountAsync();
        var (s1, _) = await SeedSessionTokenAsync(accountId, NewVerifier(), createdAt: Now.AddDays(-3));
        var (s2, _) = await SeedSessionTokenAsync(accountId, NewVerifier(), createdAt: Now.AddDays(-1)); // newest
        var (s3, _) = await SeedSessionTokenAsync(accountId, NewVerifier(), createdAt: Now.AddDays(-2));
        var (revoked, _) = await SeedSessionTokenAsync(accountId, NewVerifier(), sessionRevokedAt: Now.AddMinutes(-1)); // excluded
        var otherAccount = await SeedAccountAsync();
        await SeedSessionTokenAsync(otherAccount, NewVerifier());

        var list = await Store().ListSessionsAsync(accountId);
        var ids = list.Select(r => r.Id).ToArray();

        Assert.Equal(new[] { s2, s3, s1 }, ids);   // created_at DESC
        Assert.DoesNotContain(revoked, ids);        // unrevoked only
    }

    [Fact]
    public async Task List_IsCappedAtTheNewest200_AndReadsUtcTimestamps()
    {
        var accountId = await SeedAccountAsync();
        await using (var c = await _fixture.ConnectionFactory.OpenConnectionAsync())
        {
            // 205 sessions, one minute apart; the five oldest must be left out.
            var rows = Enumerable.Range(0, 205).Select(i => new
            {
                id = Guid.NewGuid(), accountId, createdAt = Now.AddMinutes(-205 + i), lastSeen = Now, absolute = Now.AddDays(90),
            });
            await c.ExecuteAsync(
                """
                INSERT INTO sessions (id, account_id, created_at, last_seen_at, absolute_expires_at, revoked_at, user_agent)
                VALUES (@id, @accountId, @createdAt, @lastSeen, @absolute, NULL, NULL);
                """, rows);
        }

        var list = await Store().ListSessionsAsync(accountId);

        Assert.Equal(SessionListLimits.MaxListedSessions, list.Count);
        Assert.Equal(Now.AddMinutes(-1), list[0].CreatedAt);            // newest first
        Assert.Equal(Now.AddMinutes(-200), list[^1].CreatedAt);         // the five oldest are not listed
        Assert.All(list, r => Assert.Equal(DateTimeKind.Utc, r.CreatedAt.Kind));
        Assert.All(list, r => Assert.Equal(DateTimeKind.Utc, r.LastSeenAt.Kind));
    }

    // ============================ LIST usability filter (MIN-1) ============================

    private async Task<Guid[]> ListIdsAsync(Guid accountId, TimeProvider? clock = null)
        => (await Store(clock).ListSessionsAsync(accountId)).Select(r => r.Id).ToArray();

    [Fact]
    public async Task List_ExcludesAbsoluteExpired()
    {
        var accountId = await SeedAccountAsync();
        var (expired, _) = await SeedSessionTokenAsync(accountId, NewVerifier(), absoluteExpiresAt: Now.AddHours(-1));
        var (active, _) = await SeedSessionTokenAsync(accountId, NewVerifier());
        var ids = await ListIdsAsync(accountId);
        Assert.DoesNotContain(expired, ids);
        Assert.Contains(active, ids);
    }

    [Fact]
    public async Task List_ExcludesAbsoluteExpiryExactlyNow()
    {
        var accountId = await SeedAccountAsync();
        var (boundary, _) = await SeedSessionTokenAsync(accountId, NewVerifier(), absoluteExpiresAt: Now);
        Assert.DoesNotContain(boundary, await ListIdsAsync(accountId));
    }

    [Fact]
    public async Task List_ExcludesIdleExpired()
    {
        var accountId = await SeedAccountAsync();
        var (idle, _) = await SeedSessionTokenAsync(accountId, NewVerifier(), lastSeenAt: Now.AddDays(-31), absoluteExpiresAt: Now.AddDays(90));
        Assert.DoesNotContain(idle, await ListIdsAsync(accountId));
    }

    [Fact]
    public async Task List_ExcludesIdleAgeExactlyLimit()
    {
        var accountId = await SeedAccountAsync();
        var (boundary, _) = await SeedSessionTokenAsync(accountId, NewVerifier(), lastSeenAt: Now.AddDays(-30), absoluteExpiresAt: Now.AddDays(90));
        Assert.DoesNotContain(boundary, await ListIdsAsync(accountId));
    }

    [Fact]
    public async Task List_IncludesJustInsideIdleWindow()
    {
        var accountId = await SeedAccountAsync();
        var (justInside, _) = await SeedSessionTokenAsync(accountId, NewVerifier(), lastSeenAt: Now.AddDays(-30).AddSeconds(1), absoluteExpiresAt: Now.AddDays(90));
        Assert.Contains(justInside, await ListIdsAsync(accountId));
    }

    [Fact]
    public async Task List_IncludesNormalActiveSession()
    {
        var accountId = await SeedAccountAsync();
        var (active, _) = await SeedSessionTokenAsync(accountId, NewVerifier());
        Assert.Contains(active, await ListIdsAsync(accountId));
    }

    [Fact]
    public async Task List_DependsOnTimeProvider_ExcludedWhenClockAdvancesToIdleBoundary()
    {
        var accountId = await SeedAccountAsync();
        var (sessionId, _) = await SeedSessionTokenAsync(accountId, NewVerifier(), lastSeenAt: Now, absoluteExpiresAt: Now.AddDays(90));
        Assert.Contains(sessionId, await ListIdsAsync(accountId, Clock()));                       // active at Now
        Assert.DoesNotContain(sessionId, await ListIdsAsync(accountId, Clock(Now.AddDays(30))));  // idle age == 30d after advance → excluded
    }

    // ============================ REFRESH vs REVOCATION concurrency ============================

    [Fact]
    public async Task RefreshRacingLogout_FinalSessionRevoked_ZeroActiveTokens()
    {
        var accountId = await SeedAccountAsync();
        var v0 = NewVerifier();
        var (sessionId, _) = await SeedSessionTokenAsync(accountId, v0);

        var refresh = Store().RotateAsync(new RefreshRotationRequest { PresentedVerifier = v0, NextVerifier = NewVerifier() });
        var logout = Store().LogoutAsync(accountId, sessionId);
        await Task.WhenAll(refresh, logout);

        Assert.NotNull(await SessionRevokedAtAsync(sessionId));
        Assert.Equal(0, await ActiveRefreshCountAsync(sessionId));
    }

    [Fact]
    public async Task RefreshRacingDelete_FinalSessionRevoked_ZeroActiveTokens_OtherSessionUntouched()
    {
        var accountId = await SeedAccountAsync();
        var v0 = NewVerifier();
        var (sessionId, _) = await SeedSessionTokenAsync(accountId, v0);
        var (otherSession, _) = await SeedSessionTokenAsync(accountId, NewVerifier());

        var refresh = Store().RotateAsync(new RefreshRotationRequest { PresentedVerifier = v0, NextVerifier = NewVerifier() });
        var delete = Store().DeleteSessionAsync(accountId, sessionId);
        await Task.WhenAll(refresh, delete);

        Assert.NotNull(await SessionRevokedAtAsync(sessionId));
        Assert.Equal(0, await ActiveRefreshCountAsync(sessionId));
        Assert.Null(await SessionRevokedAtAsync(otherSession));   // unrelated session untouched
        Assert.Equal(1, await ActiveRefreshCountAsync(otherSession));
    }

    // ============================ per-request auth integration ============================

    private SessionAuthenticator Authenticator(TimeProvider clock) => new(Store(clock), clock, new RefreshTokenOptions());

    [Fact]
    public async Task Auth_ValidBeforeLogout_InvalidAfter()
    {
        var accountId = await SeedAccountAsync();
        var (sessionId, _) = await SeedSessionTokenAsync(accountId, NewVerifier());
        var clock = Clock();
        Assert.Equal(SessionAuthResult.Valid, await Authenticator(clock).AuthenticateAsync(accountId, sessionId));
        await Store(clock).LogoutAsync(accountId, sessionId);
        Assert.Equal(SessionAuthResult.Invalid, await Authenticator(clock).AuthenticateAsync(accountId, sessionId));
    }

    [Fact]
    public async Task Auth_ValidBeforeDisable_InvalidAfter()
    {
        var accountId = await SeedAccountAsync();
        var (sessionId, _) = await SeedSessionTokenAsync(accountId, NewVerifier());
        var clock = Clock();
        Assert.Equal(SessionAuthResult.Valid, await Authenticator(clock).AuthenticateAsync(accountId, sessionId));
        await DisableAsync(_fixture, accountId, Now);
        Assert.Equal(SessionAuthResult.Invalid, await Authenticator(clock).AuthenticateAsync(accountId, sessionId));
    }

    [Fact]
    public async Task Auth_InvalidAfterRefreshReuseRevokesSession()
    {
        var accountId = await SeedAccountAsync();
        var v0 = NewVerifier();
        var (sessionId, _) = await SeedSessionTokenAsync(accountId, v0);
        var clock = Clock();

        Assert.Equal(SessionAuthResult.Valid, await Authenticator(clock).AuthenticateAsync(accountId, sessionId));
        Assert.Equal(RefreshRotationOutcome.Rotated, (await Store(clock).RotateAsync(new RefreshRotationRequest { PresentedVerifier = v0, NextVerifier = NewVerifier() })).Outcome);
        // Replay consumed R0 → strict reuse revokes the session.
        Assert.Equal(RefreshRotationOutcome.ReuseDetected, (await Store(Clock(Now.AddMinutes(1))).RotateAsync(new RefreshRotationRequest { PresentedVerifier = v0, NextVerifier = NewVerifier() })).Outcome);
        Assert.Equal(SessionAuthResult.Invalid, await Authenticator(clock).AuthenticateAsync(accountId, sessionId));
    }

    // ============================ cancellation ============================

    [Fact]
    public async Task Logout_AlreadyCancelled_Throws_NoMutation()
    {
        var accountId = await SeedAccountAsync();
        var (sessionId, _) = await SeedSessionTokenAsync(accountId, NewVerifier());
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => Store().LogoutAsync(accountId, sessionId, cts.Token));
        Assert.Null(await SessionRevokedAtAsync(sessionId));
    }
}
