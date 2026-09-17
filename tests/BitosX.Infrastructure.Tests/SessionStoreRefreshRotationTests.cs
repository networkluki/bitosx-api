using System.Security.Cryptography;
using BitosX.Application.Abstractions.Persistence;
using BitosX.Application.Security;
using BitosX.Infrastructure.Persistence;
using Dapper;
using Microsoft.Extensions.Time.Testing;
using MySqlConnector;

namespace BitosX.Infrastructure.Tests;

/// <summary>
/// Real-MariaDB tests for the M-1 verifier snapshot fix and strict refresh rotation/reuse.
/// Verifiers are random 32-byte values (no global token_hash collisions); the store runs on the
/// runtime DML-only connection. Sessions/tokens are inserted directly for precise timestamp control.
/// </summary>
[Collection("Persistence")]
public sealed class SessionStoreRefreshRotationTests
{
    private static readonly DateTime Now = new(2026, 9, 17, 12, 0, 0, DateTimeKind.Utc);
    private const string Phc = "$argon2id$v=19$m=8192,t=1,p=1$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYQ";

    private readonly DatabaseFixture _fixture;

    public SessionStoreRefreshRotationTests(DatabaseFixture fixture) => _fixture = fixture;

    private static FakeTimeProvider Clock(DateTime? at = null) => new(new DateTimeOffset(at ?? Now, TimeSpan.Zero));
    private SessionStore Store(TimeProvider clock, RefreshTokenOptions? options = null) => new(_fixture.RuntimeConnectionFactory, clock, options ?? new RefreshTokenOptions());
    private static byte[] NewVerifier() => RandomNumberGenerator.GetBytes(32);
    private static RefreshRotationRequest Rotate(byte[] presented, byte[] next) => new() { PresentedVerifier = presented, NextVerifier = next };

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
            """,
            new { id, email, now = Now, phc = Phc, disabledAt = disabled ? Now : (DateTime?)null });
        return id;
    }

    /// <summary>Inserts a session + one refresh row with fully controlled fields; returns their ids.</summary>
    private async Task<(Guid sessionId, Guid refreshTokenId)> SeedSessionTokenAsync(
        Guid accountId, byte[] tokenHash,
        DateTime? lastSeenAt = null, DateTime? absoluteExpiresAt = null, DateTime? sessionRevokedAt = null,
        DateTime? tokenExpiresAt = null, DateTime? tokenConsumedAt = null, DateTime? tokenRevokedAt = null, Guid? replacedBy = null)
    {
        var sessionId = Guid.NewGuid();
        var refreshTokenId = Guid.NewGuid();
        await using var c = await _fixture.ConnectionFactory.OpenConnectionAsync();
        await c.ExecuteAsync(
            """
            INSERT INTO sessions (id, account_id, created_at, last_seen_at, absolute_expires_at, revoked_at, user_agent)
            VALUES (@sessionId, @accountId, @now, @lastSeen, @absolute, @sessionRevoked, NULL);
            """,
            new { sessionId, accountId, now = Now, lastSeen = lastSeenAt ?? Now, absolute = absoluteExpiresAt ?? Now.AddDays(90), sessionRevoked = sessionRevokedAt });
        await c.ExecuteAsync(
            """
            INSERT INTO refresh_tokens (id, session_id, token_hash, created_at, expires_at, consumed_at, revoked_at, replaced_by_token_id)
            VALUES (@refreshTokenId, @sessionId, @tokenHash, @now, @expires, @consumed, @revoked, @replacedBy);
            """,
            new { refreshTokenId, sessionId, tokenHash, now = Now, expires = tokenExpiresAt ?? Now.AddDays(30), consumed = tokenConsumedAt, revoked = tokenRevokedAt, replacedBy });
        return (sessionId, refreshTokenId);
    }

    private async Task InsertExtraTokenAsync(Guid sessionId, byte[] tokenHash)
    {
        await using var c = await _fixture.ConnectionFactory.OpenConnectionAsync();
        await c.ExecuteAsync(
            """
            INSERT INTO refresh_tokens (id, session_id, token_hash, created_at, expires_at, consumed_at, revoked_at, replaced_by_token_id)
            VALUES (@id, @sessionId, @tokenHash, @now, @expires, NULL, NULL, NULL);
            """,
            new { id = Guid.NewGuid(), sessionId, tokenHash, now = Now, expires = Now.AddDays(30) });
    }

    private async Task<T> ScalarAsync<T>(string sql, object p)
    {
        await using var c = await _fixture.ConnectionFactory.OpenConnectionAsync();
        return (await c.ExecuteScalarAsync<T>(sql, p))!;
    }

    private async Task<dynamic?> RefreshByHashAsync(byte[] hash)
    {
        await using var c = await _fixture.ConnectionFactory.OpenConnectionAsync();
        return await c.QuerySingleOrDefaultAsync(
            "SELECT session_id AS SessionId, consumed_at AS ConsumedAt, revoked_at AS RevokedAt, replaced_by_token_id AS ReplacedByTokenId FROM refresh_tokens WHERE token_hash=@hash;",
            new { hash });
    }

    private async Task<dynamic> RefreshByIdAsync(Guid id)
    {
        await using var c = await _fixture.ConnectionFactory.OpenConnectionAsync();
        return await c.QuerySingleAsync(
            "SELECT consumed_at AS ConsumedAt, revoked_at AS RevokedAt, replaced_by_token_id AS ReplacedByTokenId FROM refresh_tokens WHERE id=@id;",
            new { id });
    }

    private async Task<dynamic> SessionByIdAsync(Guid id)
    {
        await using var c = await _fixture.ConnectionFactory.OpenConnectionAsync();
        return await c.QuerySingleAsync("SELECT revoked_at AS RevokedAt, last_seen_at AS LastSeenAt FROM sessions WHERE id=@id;", new { id });
    }

    private Task<int> ActiveRefreshCountAsync(Guid sessionId)
        => ScalarAsync<int>("SELECT COUNT(*) FROM refresh_tokens WHERE session_id=@sid AND consumed_at IS NULL AND revoked_at IS NULL;", new { sid = sessionId });

    // ============================ M-1: CreateOnLogin verifier snapshot ============================

    [Fact]
    public async Task CreateOnLogin_VerifierMutatedDuringLock_StoresOriginalSnapshot()
    {
        var accountId = await SeedAccountAsync();
        var email = await ScalarAsync<string>("SELECT normalized_email FROM accounts WHERE id=@id;", new { id = accountId });
        var original = NewVerifier();
        var callerArray = (byte[])original.Clone();

        await using var lockConn = await _fixture.ConnectionFactory.OpenConnectionAsync();
        await using var lockTx = await lockConn.BeginTransactionAsync();
        await lockConn.ExecuteAsync(new CommandDefinition("SELECT id FROM accounts WHERE id=@id FOR UPDATE;", new { id = accountId }, lockTx));

        var request = new LoginSessionCreateRequest { AccountId = accountId, NormalizedEmail = email, ExpectedPasswordHash = Phc, InitialRefreshVerifier = callerArray };
        var task = Store(Clock()).CreateOnLoginAsync(request);

        await Task.Delay(200);
        Assert.False(task.IsCompleted); // waiting on the held account lock
        RandomNumberGenerator.Fill(callerArray); // mutate after the snapshot must have been taken

        await lockTx.CommitAsync();
        var result = await task;

        Assert.Equal(LoginSessionCreateOutcome.Created, result.Outcome);
        Assert.NotNull(await RefreshByHashAsync(original));       // original snapshot persisted
        Assert.Null(await RefreshByHashAsync(callerArray));       // mutated value never stored
    }

    // ============================ Rotation success ============================

    [Fact]
    public async Task Rotate_ActiveR0_Rotated_WithAllSuccessInvariants()
    {
        var accountId = await SeedAccountAsync();
        var v0 = NewVerifier();
        var v1 = NewVerifier();
        var (sessionId, r0Id) = await SeedSessionTokenAsync(accountId, v0);
        var at = Now.AddHours(1);

        var result = await Store(Clock(at)).RotateAsync(Rotate(v0, v1));

        Assert.Equal(RefreshRotationOutcome.Rotated, result.Outcome);
        Assert.Equal(accountId, result.AccountId);
        Assert.Equal(sessionId, result.SessionId);
        Assert.Equal(at, result.RotatedAt);
        Assert.Equal(at.AddDays(30), result.NextRefreshExpiresAt); // min(now+30d, absolute now+90d... absolute is Now+90d)

        var r0 = await RefreshByIdAsync(r0Id);
        Assert.NotNull(r0.ConsumedAt);
        Assert.Null(r0.RevokedAt);
        Assert.NotNull(r0.ReplacedByTokenId);

        var r1 = await RefreshByHashAsync(v1);
        Assert.NotNull(r1);
        Assert.Equal(sessionId, (Guid)r1!.SessionId);
        Assert.Null(r1.ConsumedAt);
        Assert.Null(r1.RevokedAt);
        Assert.Null(r1.ReplacedByTokenId);

        var session = await SessionByIdAsync(sessionId);
        Assert.Null(session.RevokedAt);
        Assert.Equal(at, (DateTime)session.LastSeenAt); // last_seen_at bumped to authoritative now

        Assert.Equal(1, await ActiveRefreshCountAsync(sessionId)); // exactly one active token (R1)
    }

    [Fact]
    public async Task Rotate_ClampsR1ExpiryToAbsolute_WhenIdleExceedsRemainingAbsolute()
    {
        var accountId = await SeedAccountAsync();
        var v0 = NewVerifier();
        var v1 = NewVerifier();
        // Absolute expiry only 5 days out; idle lifetime 30d → clamp R1 expiry to absolute.
        var (sessionId, _) = await SeedSessionTokenAsync(accountId, v0, absoluteExpiresAt: Now.AddDays(5));

        var result = await Store(Clock()).RotateAsync(Rotate(v0, v1));
        Assert.Equal(RefreshRotationOutcome.Rotated, result.Outcome);
        Assert.Equal(Now.AddDays(5), result.NextRefreshExpiresAt); // clamped to absolute
    }

    // ============================ Invalid (no revocation, no mutation) ============================

    private async Task AssertInvalidNoMutationAsync(Guid sessionId, Guid r0Id, byte[] v0, byte[] v1, DateTime? at = null)
    {
        var lastSeenBefore = (DateTime)(await SessionByIdAsync(sessionId)).LastSeenAt;
        var result = await Store(Clock(at)).RotateAsync(Rotate(v0, v1));
        Assert.Equal(RefreshRotationOutcome.Invalid, result.Outcome);
        Assert.Null(await RefreshByHashAsync(v1));                 // no new refresh row
        var r0 = await RefreshByIdAsync(r0Id);
        Assert.Null(r0.ConsumedAt);                                // R0 untouched
        Assert.Null(r0.ReplacedByTokenId);
        Assert.Equal(lastSeenBefore, (DateTime)(await SessionByIdAsync(sessionId)).LastSeenAt); // last_seen unchanged
    }

    [Fact]
    public async Task Rotate_UnknownVerifier_Invalid()
    {
        var result = await Store(Clock()).RotateAsync(Rotate(NewVerifier(), NewVerifier()));
        Assert.Equal(RefreshRotationOutcome.Invalid, result.Outcome);
    }

    [Fact]
    public async Task Rotate_DisabledAccount_Invalid()
    {
        var accountId = await SeedAccountAsync(disabled: true);
        var v0 = NewVerifier();
        var (sessionId, r0Id) = await SeedSessionTokenAsync(accountId, v0);
        await AssertInvalidNoMutationAsync(sessionId, r0Id, v0, NewVerifier());
    }

    [Fact]
    public async Task Rotate_SessionAlreadyRevoked_ActiveToken_Invalid()
    {
        var accountId = await SeedAccountAsync();
        var v0 = NewVerifier();
        var (sessionId, r0Id) = await SeedSessionTokenAsync(accountId, v0, sessionRevokedAt: Now.AddMinutes(-5));
        await AssertInvalidNoMutationAsync(sessionId, r0Id, v0, NewVerifier());
    }

    [Fact]
    public async Task Rotate_AbsoluteExpiryPast_Invalid()
    {
        var accountId = await SeedAccountAsync();
        var v0 = NewVerifier();
        var (sessionId, r0Id) = await SeedSessionTokenAsync(accountId, v0, absoluteExpiresAt: Now.AddHours(-1));
        await AssertInvalidNoMutationAsync(sessionId, r0Id, v0, NewVerifier());
    }

    [Fact]
    public async Task Rotate_AbsoluteExpiryExactlyNow_Invalid()
    {
        var accountId = await SeedAccountAsync();
        var v0 = NewVerifier();
        var (sessionId, r0Id) = await SeedSessionTokenAsync(accountId, v0, absoluteExpiresAt: Now);
        await AssertInvalidNoMutationAsync(sessionId, r0Id, v0, NewVerifier());
    }

    [Fact]
    public async Task Rotate_IdleAgeOverLimit_Invalid()
    {
        var accountId = await SeedAccountAsync();
        var v0 = NewVerifier();
        var (sessionId, r0Id) = await SeedSessionTokenAsync(accountId, v0, lastSeenAt: Now.AddDays(-31));
        await AssertInvalidNoMutationAsync(sessionId, r0Id, v0, NewVerifier());
    }

    [Fact]
    public async Task Rotate_IdleAgeExactlyLimit_Invalid()
    {
        var accountId = await SeedAccountAsync();
        var v0 = NewVerifier();
        var (sessionId, r0Id) = await SeedSessionTokenAsync(accountId, v0, lastSeenAt: Now.AddDays(-30));
        await AssertInvalidNoMutationAsync(sessionId, r0Id, v0, NewVerifier());
    }

    [Fact]
    public async Task Rotate_TokenExpiryPast_Invalid()
    {
        var accountId = await SeedAccountAsync();
        var v0 = NewVerifier();
        var (sessionId, r0Id) = await SeedSessionTokenAsync(accountId, v0, tokenExpiresAt: Now.AddHours(-1));
        await AssertInvalidNoMutationAsync(sessionId, r0Id, v0, NewVerifier());
    }

    [Fact]
    public async Task Rotate_TokenExpiryExactlyNow_Invalid()
    {
        var accountId = await SeedAccountAsync();
        var v0 = NewVerifier();
        var (sessionId, r0Id) = await SeedSessionTokenAsync(accountId, v0, tokenExpiresAt: Now);
        await AssertInvalidNoMutationAsync(sessionId, r0Id, v0, NewVerifier());
    }

    // ============================ Strict reuse ============================

    [Fact]
    public async Task Rotate_ConsumedTokenPresentedAgain_ReuseDetected_SessionAndR1Revoked_NoR2()
    {
        var accountId = await SeedAccountAsync();
        var v0 = NewVerifier();
        var v1 = NewVerifier();
        var v2 = NewVerifier();
        var (sessionId, _) = await SeedSessionTokenAsync(accountId, v0);

        // Legitimate rotation R0 -> R1.
        Assert.Equal(RefreshRotationOutcome.Rotated, (await Store(Clock()).RotateAsync(Rotate(v0, v1))).Outcome);

        // Present the now-consumed R0 again → strict reuse.
        var reuse = await Store(Clock(Now.AddMinutes(1))).RotateAsync(Rotate(v0, v2));
        Assert.Equal(RefreshRotationOutcome.ReuseDetected, reuse.Outcome);

        Assert.NotNull((await SessionByIdAsync(sessionId)).RevokedAt);        // session revoked
        Assert.NotNull((await RefreshByHashAsync(v1))!.RevokedAt);            // R1 revoked
        Assert.Null(await RefreshByHashAsync(v2));                            // no R2 inserted
        Assert.Equal(0, await ActiveRefreshCountAsync(sessionId));           // no active tokens remain
    }

    [Fact]
    public async Task Rotate_AttackerFirstThenLegitimateReplaysR0_SessionContained()
    {
        // attacker steals R0, rotates first -> R1(attacker); legit client replays R0 -> strict reuse.
        var accountId = await SeedAccountAsync();
        var v0 = NewVerifier();
        var attackerNext = NewVerifier();
        var legitNext = NewVerifier();
        var (sessionId, _) = await SeedSessionTokenAsync(accountId, v0);

        Assert.Equal(RefreshRotationOutcome.Rotated, (await Store(Clock()).RotateAsync(Rotate(v0, attackerNext))).Outcome);
        Assert.Equal(RefreshRotationOutcome.ReuseDetected, (await Store(Clock(Now.AddMinutes(1))).RotateAsync(Rotate(v0, legitNext))).Outcome);

        Assert.NotNull((await SessionByIdAsync(sessionId)).RevokedAt);
        Assert.NotNull((await RefreshByHashAsync(attackerNext))!.RevokedAt); // attacker R1 revoked
        Assert.Equal(0, await ActiveRefreshCountAsync(sessionId));
    }

    [Fact]
    public async Task Rotate_ResponseLostClientRetriesR0_ReuseDetected()
    {
        var accountId = await SeedAccountAsync();
        var v0 = NewVerifier();
        var v1 = NewVerifier();
        var (sessionId, _) = await SeedSessionTokenAsync(accountId, v0);

        Assert.Equal(RefreshRotationOutcome.Rotated, (await Store(Clock()).RotateAsync(Rotate(v0, v1))).Outcome);
        // Client never got R1 and retries R0 (single-flight would prevent this; strict reuse revokes).
        Assert.Equal(RefreshRotationOutcome.ReuseDetected, (await Store(Clock(Now.AddMinutes(1))).RotateAsync(Rotate(v0, NewVerifier()))).Outcome);
        Assert.NotNull((await SessionByIdAsync(sessionId)).RevokedAt);
        Assert.NotNull((await RefreshByHashAsync(v1))!.RevokedAt);
    }

    [Fact]
    public async Task Rotate_AlreadyRevokedTokenPresented_ReuseDetected_RevokesSessionAndActiveTokens()
    {
        var accountId = await SeedAccountAsync();
        var v0 = NewVerifier();
        var vOther = NewVerifier();
        var (sessionId, _) = await SeedSessionTokenAsync(accountId, v0, tokenRevokedAt: Now.AddMinutes(-10));
        await InsertExtraTokenAsync(sessionId, vOther); // another active token in the same session

        var reuse = await Store(Clock()).RotateAsync(Rotate(v0, NewVerifier()));
        Assert.Equal(RefreshRotationOutcome.ReuseDetected, reuse.Outcome);
        Assert.NotNull((await SessionByIdAsync(sessionId)).RevokedAt);
        Assert.NotNull((await RefreshByHashAsync(vOther))!.RevokedAt); // sibling active token revoked
        Assert.Equal(0, await ActiveRefreshCountAsync(sessionId));
    }

    [Fact]
    public async Task Rotate_ReuseInSessionA_DoesNotAffectSessionB()
    {
        var accountId = await SeedAccountAsync();
        var v0a = NewVerifier();
        var v1a = NewVerifier();
        var v0b = NewVerifier();
        var (sessionA, _) = await SeedSessionTokenAsync(accountId, v0a);
        var (sessionB, _) = await SeedSessionTokenAsync(accountId, v0b);

        Assert.Equal(RefreshRotationOutcome.Rotated, (await Store(Clock()).RotateAsync(Rotate(v0a, v1a))).Outcome);
        Assert.Equal(RefreshRotationOutcome.ReuseDetected, (await Store(Clock(Now.AddMinutes(1))).RotateAsync(Rotate(v0a, NewVerifier()))).Outcome);

        Assert.NotNull((await SessionByIdAsync(sessionA)).RevokedAt);   // A contained
        Assert.Equal(0, await ActiveRefreshCountAsync(sessionA));
        Assert.Null((await SessionByIdAsync(sessionB)).RevokedAt);      // B untouched
        Assert.Equal(1, await ActiveRefreshCountAsync(sessionB));       // B's token still active
    }

    // ============================ Concurrency ============================

    [Fact]
    public async Task Rotate_TwoConcurrentSameR0_OneRotatedOneReuse_SessionRevoked_NoActiveTokens()
    {
        var accountId = await SeedAccountAsync();
        var v0 = NewVerifier();
        var (sessionId, r0Id) = await SeedSessionTokenAsync(accountId, v0);

        var t1 = Store(Clock()).RotateAsync(Rotate(v0, NewVerifier()));
        var t2 = Store(Clock()).RotateAsync(Rotate(v0, NewVerifier()));
        var results = await Task.WhenAll(t1, t2);

        var outcomes = results.Select(r => r.Outcome).OrderBy(o => o).ToArray();
        Assert.Equal(new[] { RefreshRotationOutcome.Rotated, RefreshRotationOutcome.ReuseDetected }.OrderBy(o => o).ToArray(), outcomes);

        Assert.NotNull((await SessionByIdAsync(sessionId)).RevokedAt);  // session revoked by reuse loser
        Assert.NotNull((await RefreshByIdAsync(r0Id)).ConsumedAt);      // R0 consumed by winner
        Assert.Equal(0, await ActiveRefreshCountAsync(sessionId));      // winner's R1 revoked → none active
    }

    // ============================ Next-verifier collision ============================

    [Fact]
    public async Task Rotate_NextVerifierCollision_ThrowsAndRollsBack_R0RemainsActive()
    {
        var accountId = await SeedAccountAsync();
        var v0 = NewVerifier();
        var vCollide = NewVerifier();
        var (sessionId, r0Id) = await SeedSessionTokenAsync(accountId, v0);
        await InsertExtraTokenAsync(sessionId, vCollide); // occupies the token_hash NextVerifier will collide with

        var lastSeenBefore = (DateTime)(await SessionByIdAsync(sessionId)).LastSeenAt;
        await Assert.ThrowsAsync<MySqlException>(() => Store(Clock()).RotateAsync(Rotate(v0, vCollide)));

        var r0 = await RefreshByIdAsync(r0Id);
        Assert.Null(r0.ConsumedAt);        // R0 rolled back to active
        Assert.Null(r0.ReplacedByTokenId);
        Assert.Equal(lastSeenBefore, (DateTime)(await SessionByIdAsync(sessionId)).LastSeenAt);
    }

    // ============================ Verifier mutation during rotate ============================

    [Fact]
    public async Task Rotate_VerifiersMutatedDuringLock_UsesOriginalSnapshots()
    {
        var accountId = await SeedAccountAsync();
        var v0 = NewVerifier();
        var nextOriginal = NewVerifier();
        var presentedCaller = (byte[])v0.Clone();
        var nextCaller = (byte[])nextOriginal.Clone();
        var (sessionId, _) = await SeedSessionTokenAsync(accountId, v0);

        await using var lockConn = await _fixture.ConnectionFactory.OpenConnectionAsync();
        await using var lockTx = await lockConn.BeginTransactionAsync();
        await lockConn.ExecuteAsync(new CommandDefinition("SELECT id FROM accounts WHERE id=@id FOR UPDATE;", new { id = accountId }, lockTx));

        var task = Store(Clock()).RotateAsync(Rotate(presentedCaller, nextCaller));
        await Task.Delay(200);
        Assert.False(task.IsCompleted); // blocked acquiring the account lock
        RandomNumberGenerator.Fill(presentedCaller);
        RandomNumberGenerator.Fill(nextCaller);

        await lockTx.CommitAsync();
        var result = await task;

        Assert.Equal(RefreshRotationOutcome.Rotated, result.Outcome); // presented snapshot located R0
        Assert.NotNull(await RefreshByHashAsync(nextOriginal));       // R1 stored the ORIGINAL next
        Assert.Null(await RefreshByHashAsync(nextCaller));            // mutated value never stored
    }

    // ============================ Authoritative time after lock ============================

    [Fact]
    public async Task Rotate_AuthoritativeTimeReadAfterLock()
    {
        var accountId = await SeedAccountAsync();
        var v0 = NewVerifier();
        var v1 = NewVerifier();
        var (sessionId, _) = await SeedSessionTokenAsync(accountId, v0);
        var clock = Clock(); // starts at Now

        await using var lockConn = await _fixture.ConnectionFactory.OpenConnectionAsync();
        await using var lockTx = await lockConn.BeginTransactionAsync();
        await lockConn.ExecuteAsync(new CommandDefinition("SELECT id FROM accounts WHERE id=@id FOR UPDATE;", new { id = accountId }, lockTx));

        var task = Store(clock).RotateAsync(Rotate(v0, v1));
        await Task.Delay(200);
        Assert.False(task.IsCompleted);
        var advanced = Now.AddHours(2);
        clock.SetUtcNow(new DateTimeOffset(advanced, TimeSpan.Zero)); // advance while blocked before the lock

        await lockTx.CommitAsync();
        var result = await task;

        Assert.Equal(RefreshRotationOutcome.Rotated, result.Outcome);
        Assert.Equal(advanced, result.RotatedAt); // now was read AFTER acquiring the locks
        Assert.Equal(advanced, (DateTime)(await SessionByIdAsync(sessionId)).LastSeenAt);
    }

    // ============================ Input validation ============================

    [Fact]
    public async Task Rotate_NullPresented_Throws()
        => await Assert.ThrowsAsync<ArgumentNullException>(() => Store(Clock()).RotateAsync(new RefreshRotationRequest { PresentedVerifier = null!, NextVerifier = NewVerifier() }));

    [Fact]
    public async Task Rotate_NullNext_Throws()
        => await Assert.ThrowsAsync<ArgumentNullException>(() => Store(Clock()).RotateAsync(new RefreshRotationRequest { PresentedVerifier = NewVerifier(), NextVerifier = null! }));

    [Fact]
    public async Task Rotate_PresentedWrongLength_Throws()
        => await Assert.ThrowsAsync<ArgumentException>(() => Store(Clock()).RotateAsync(Rotate(new byte[31], NewVerifier())));

    [Fact]
    public async Task Rotate_NextWrongLength_Throws()
        => await Assert.ThrowsAsync<ArgumentException>(() => Store(Clock()).RotateAsync(Rotate(NewVerifier(), new byte[33])));

    // ============================ Cancellation ============================

    [Fact]
    public async Task Rotate_AlreadyCancelledToken_ThrowsOperationCanceled_NoMutation()
    {
        var accountId = await SeedAccountAsync();
        var v0 = NewVerifier();
        var (sessionId, r0Id) = await SeedSessionTokenAsync(accountId, v0);
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => Store(Clock()).RotateAsync(Rotate(v0, NewVerifier()), cts.Token));

        var r0 = await RefreshByIdAsync(r0Id);
        Assert.Null(r0.ConsumedAt); // no mutation on cancellation
        Assert.Null((await SessionByIdAsync(sessionId)).RevokedAt);
    }
}
