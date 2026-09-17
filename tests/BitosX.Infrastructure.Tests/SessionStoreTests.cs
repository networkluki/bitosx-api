using System.Security.Cryptography;
using BitosX.Application.Abstractions.Persistence;
using BitosX.Application.Security;
using BitosX.Infrastructure.Persistence;
using Dapper;
using Microsoft.Extensions.Time.Testing;
using MySqlConnector;

namespace BitosX.Infrastructure.Tests;

/// <summary>
/// Real-MariaDB persistence tests for atomic login session-create. The store runs on the
/// runtime DML-only connection (§15); arrangement inserts and assertion reads use the fixture
/// connection. No production DB is touched.
/// </summary>
[Collection("Persistence")]
public sealed class SessionStoreTests
{
    private static readonly DateTime Now = new(2026, 9, 17, 12, 0, 0, DateTimeKind.Utc);
    private const string PhcA = "$argon2id$v=19$m=8192,t=1,p=1$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYQ";
    private const string PhcB = "$argon2id$v=19$m=8192,t=1,p=1$b3RoZXJzYWx0b3RoZXI$b3RoZXJoYXNob3RoZXJoYXNob3RoZXI";

    private readonly DatabaseFixture _fixture;

    public SessionStoreTests(DatabaseFixture fixture) => _fixture = fixture;

    private SessionStore Store(TimeProvider clock, RefreshTokenOptions? options = null)
        => new(_fixture.RuntimeConnectionFactory, clock, options ?? new RefreshTokenOptions());

    private static FakeTimeProvider Clock(DateTime? at = null) => new(new DateTimeOffset(at ?? Now, TimeSpan.Zero));

    private static byte[] Verifier(byte seed) => Enumerable.Repeat(seed, 32).ToArray();

    private async Task<(Guid accountId, string normalizedEmail)> SeedAccountAsync(
        bool verified = true, bool disabled = false, string? passwordHash = PhcA)
    {
        var id = Guid.NewGuid();
        var email = $"user-{id:N}@example.com";
        var normalized = email; // already lowercase-canonical for the test
        await using var c = await _fixture.ConnectionFactory.OpenConnectionAsync();
        await c.ExecuteAsync(
            """
            INSERT INTO accounts (id, email, normalized_email, email_verified_at, phone_e164, phone_verified_at,
                                  password_hash, created_at, updated_at, disabled_at)
            VALUES (@id, @email, @normalized, @verifiedAt, NULL, NULL, @phc, @now, @now, @disabledAt);
            """,
            new { id, email, normalized, verifiedAt = verified ? Now : (DateTime?)null, phc = passwordHash, now = Now, disabledAt = disabled ? Now : (DateTime?)null });
        return (id, normalized);
    }

    private static LoginSessionCreateRequest Request(Guid accountId, string normalizedEmail, byte[]? verifier = null, string phc = PhcA, string? userAgent = null)
        => new()
        {
            AccountId = accountId,
            NormalizedEmail = normalizedEmail,
            ExpectedPasswordHash = phc,
            InitialRefreshVerifier = verifier ?? Verifier(0x11),
            UserAgent = userAgent,
        };

    private async Task<T> ScalarAsync<T>(string sql, object p)
    {
        await using var c = await _fixture.ConnectionFactory.OpenConnectionAsync();
        return (await c.ExecuteScalarAsync<T>(sql, p))!;
    }

    private Task<int> SessionCountAsync(Guid accountId) => ScalarAsync<int>("SELECT COUNT(*) FROM sessions WHERE account_id=@accountId;", new { accountId });
    private Task<int> RefreshCountForSessionAsync(Guid sessionId) => ScalarAsync<int>("SELECT COUNT(*) FROM refresh_tokens WHERE session_id=@sessionId;", new { sessionId });

    // ---- SUCCESS ----

    [Fact]
    public async Task Create_VerifiedAccountExactPhc_ReturnsCreated_WithOneSessionAndRefresh()
    {
        var (accountId, email) = await SeedAccountAsync();
        var verifier = Verifier(0x22);
        var result = await Store(Clock()).CreateOnLoginAsync(Request(accountId, email, verifier));

        Assert.Equal(LoginSessionCreateOutcome.Created, result.Outcome);
        Assert.Equal(accountId, result.AccountId);
        Assert.NotEqual(Guid.Empty, result.SessionId);
        Assert.Equal(1, await SessionCountAsync(accountId));
        Assert.Equal(1, await RefreshCountForSessionAsync(result.SessionId));

        // token_hash exactly equals the supplied 32-byte verifier; refresh belongs to the session.
        await using var c = await _fixture.ConnectionFactory.OpenConnectionAsync();
        var row = await c.QuerySingleAsync(
            "SELECT token_hash AS TokenHash, session_id AS SessionId, consumed_at AS ConsumedAt, revoked_at AS RevokedAt, replaced_by_token_id AS ReplacedByTokenId FROM refresh_tokens WHERE session_id=@sid;",
            new { sid = result.SessionId });
        Assert.Equal(verifier, (byte[])row.TokenHash);
        Assert.Equal(result.SessionId, (Guid)row.SessionId);
        Assert.Null(row.ConsumedAt);
        Assert.Null(row.RevokedAt);
        Assert.Null(row.ReplacedByTokenId);
    }

    [Fact]
    public async Task Create_SetsTimestampsAndExpiries_FromAuthoritativeNow()
    {
        var (accountId, email) = await SeedAccountAsync();
        var options = new RefreshTokenOptions { IdleLifetime = TimeSpan.FromDays(30), AbsoluteLifetime = TimeSpan.FromDays(90) };
        var result = await Store(Clock(), options).CreateOnLoginAsync(Request(accountId, email, Verifier(0x60)));

        Assert.Equal(Now, result.SessionCreatedAt);
        Assert.Equal(Now.AddDays(90), result.SessionAbsoluteExpiresAt);
        Assert.Equal(Now.AddDays(30), result.RefreshTokenExpiresAt); // min(now+30d, now+90d)

        await using var c = await _fixture.ConnectionFactory.OpenConnectionAsync();
        var s = await c.QuerySingleAsync(
            "SELECT created_at AS CreatedAt, last_seen_at AS LastSeenAt, absolute_expires_at AS AbsoluteExpiresAt, revoked_at AS RevokedAt FROM sessions WHERE id=@id;",
            new { id = result.SessionId });
        Assert.Equal(result.SessionCreatedAt, (DateTime)s.CreatedAt);
        Assert.Equal((DateTime)s.CreatedAt, (DateTime)s.LastSeenAt); // created_at == last_seen_at
        Assert.Equal(result.SessionAbsoluteExpiresAt, (DateTime)s.AbsoluteExpiresAt);
        Assert.Null(s.RevokedAt);
    }

    [Fact]
    public async Task Create_ClampsRefreshExpiryToAbsolute_WhenIdleExceedsAbsolute()
    {
        var (accountId, email) = await SeedAccountAsync();
        var options = new RefreshTokenOptions { IdleLifetime = TimeSpan.FromDays(200), AbsoluteLifetime = TimeSpan.FromDays(90) };
        var result = await Store(Clock(), options).CreateOnLoginAsync(Request(accountId, email, Verifier(0x61)));

        Assert.Equal(Now.AddDays(90), result.SessionAbsoluteExpiresAt);
        Assert.Equal(Now.AddDays(90), result.RefreshTokenExpiresAt); // clamped to absolute
    }

    [Fact]
    public async Task Create_UsesTimeProviderValue()
    {
        var (accountId, email) = await SeedAccountAsync();
        var custom = new DateTime(2026, 10, 1, 8, 30, 0, DateTimeKind.Utc);
        var result = await Store(Clock(custom)).CreateOnLoginAsync(Request(accountId, email, Verifier(0x62)));
        Assert.Equal(custom, result.SessionCreatedAt);
    }

    [Fact]
    public async Task Create_StoresUserAgent_WhenProvided()
    {
        var (accountId, email) = await SeedAccountAsync();
        var result = await Store(Clock()).CreateOnLoginAsync(Request(accountId, email, Verifier(0x63), userAgent: "BitosX-Desktop/1.0"));
        var ua = await ScalarAsync<string?>("SELECT user_agent FROM sessions WHERE id=@id;", new { id = result.SessionId });
        Assert.Equal("BitosX-Desktop/1.0", ua);
    }

    // ---- STATE RECHECK (all → InvalidAccountState, no rows) ----

    private async Task AssertInvalidNoRowsAsync(Guid accountId, LoginSessionCreateRequest request)
    {
        var result = await Store(Clock()).CreateOnLoginAsync(request);
        Assert.Equal(LoginSessionCreateOutcome.InvalidAccountState, result.Outcome);
        Assert.Equal(0, await SessionCountAsync(accountId));
    }

    [Fact]
    public async Task Create_MissingAccount_InvalidNoRows()
    {
        var missing = Guid.NewGuid();
        await AssertInvalidNoRowsAsync(missing, Request(missing, "ghost@example.com"));
    }

    [Fact]
    public async Task Create_NormalizedEmailMismatch_InvalidNoRows()
    {
        var (accountId, _) = await SeedAccountAsync();
        await AssertInvalidNoRowsAsync(accountId, Request(accountId, "different@example.com"));
    }

    [Fact]
    public async Task Create_EmailNotVerified_InvalidNoRows()
    {
        var (accountId, email) = await SeedAccountAsync(verified: false);
        await AssertInvalidNoRowsAsync(accountId, Request(accountId, email));
    }

    [Fact]
    public async Task Create_NullPasswordHash_InvalidNoRows()
    {
        var (accountId, email) = await SeedAccountAsync(passwordHash: null);
        await AssertInvalidNoRowsAsync(accountId, Request(accountId, email));
    }

    [Fact]
    public async Task Create_DisabledAccount_InvalidNoRows()
    {
        var (accountId, email) = await SeedAccountAsync(disabled: true);
        await AssertInvalidNoRowsAsync(accountId, Request(accountId, email));
    }

    [Fact]
    public async Task Create_PhcChangedInDb_InvalidNoRows()
    {
        // Stored PHC is PhcB, but the caller verified PhcA → exact-string re-check fails (PHC race, §12).
        var (accountId, email) = await SeedAccountAsync(passwordHash: PhcB);
        await AssertInvalidNoRowsAsync(accountId, Request(accountId, email, phc: PhcA));
    }

    // ---- INPUT VALIDATION (programmer errors, not credential outcomes) ----

    [Fact]
    public async Task Create_EmptyAccountId_Throws()
        => await Assert.ThrowsAsync<ArgumentException>(() => Store(Clock()).CreateOnLoginAsync(Request(Guid.Empty, "a@example.com")));

    [Fact]
    public async Task Create_BlankNormalizedEmail_Throws()
        => await Assert.ThrowsAsync<ArgumentException>(() => Store(Clock()).CreateOnLoginAsync(Request(Guid.NewGuid(), "   ")));

    [Fact]
    public async Task Create_BlankExpectedPhc_Throws()
        => await Assert.ThrowsAsync<ArgumentException>(() => Store(Clock()).CreateOnLoginAsync(Request(Guid.NewGuid(), "a@example.com", phc: "")));

    [Fact]
    public async Task Create_NullVerifier_Throws()
    {
        var req = new LoginSessionCreateRequest { AccountId = Guid.NewGuid(), NormalizedEmail = "a@example.com", ExpectedPasswordHash = PhcA, InitialRefreshVerifier = null! };
        await Assert.ThrowsAsync<ArgumentNullException>(() => Store(Clock()).CreateOnLoginAsync(req));
    }

    [Fact]
    public async Task Create_VerifierWrongLength_Throws()
    {
        var req = Request(Guid.NewGuid(), "a@example.com", verifier: new byte[31]);
        await Assert.ThrowsAsync<ArgumentException>(() => Store(Clock()).CreateOnLoginAsync(req));
    }

    [Fact]
    public async Task Create_UserAgentTooLong_Throws()
        => await Assert.ThrowsAsync<ArgumentException>(() => Store(Clock()).CreateOnLoginAsync(Request(Guid.NewGuid(), "a@example.com", userAgent: new string('x', 256))));

    // ---- ATOMICITY: duplicate token_hash rolls back the new session ----

    [Fact]
    public async Task Create_DuplicateVerifier_FailsAndRollsBackNewSession()
    {
        var (accountId, email) = await SeedAccountAsync();
        var verifier = Verifier(0x33);
        var first = await Store(Clock()).CreateOnLoginAsync(Request(accountId, email, verifier));
        Assert.Equal(LoginSessionCreateOutcome.Created, first.Outcome);

        // A second login-create forced to reuse the exact same 32-byte verifier violates the UNIQUE
        // token_hash constraint → unexpected persistence failure, new session NOT committed.
        await Assert.ThrowsAsync<MySqlException>(() => Store(Clock()).CreateOnLoginAsync(Request(accountId, email, verifier)));

        Assert.Equal(1, await SessionCountAsync(accountId)); // only the first session survives
    }

    // ---- CONCURRENCY: two valid logins, distinct verifiers → two sessions ----

    [Fact]
    public async Task Create_TwoConcurrentLogins_SameAccount_ProduceTwoDistinctSessions()
    {
        var (accountId, email) = await SeedAccountAsync();
        var t1 = Store(Clock()).CreateOnLoginAsync(Request(accountId, email, Verifier(0x44)));
        var t2 = Store(Clock()).CreateOnLoginAsync(Request(accountId, email, Verifier(0x55)));
        var results = await Task.WhenAll(t1, t2);

        Assert.All(results, r => Assert.Equal(LoginSessionCreateOutcome.Created, r.Outcome));
        Assert.NotEqual(results[0].SessionId, results[1].SessionId);
        Assert.Equal(2, await SessionCountAsync(accountId));
    }
}
