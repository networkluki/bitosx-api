using System.Security.Cryptography;
using BitosX.Application.Housekeeping;
using BitosX.Application.Security;
using BitosX.Infrastructure.Housekeeping;
using BitosX.Infrastructure.Persistence;
using Dapper;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;

namespace BitosX.Infrastructure.Tests;

/// <summary>
/// Housekeeping against the test DB (runtime DML account): dead challenges and sessions older than the retention
/// window go, with their outbox rows and refresh tokens; everything live or recently dead stays.
/// </summary>
[Collection("Persistence")]
public sealed class HousekeepingTests
{
    private static readonly DateTime Now = new(2027, 6, 1, 12, 0, 0, DateTimeKind.Utc); // after every fixed test date
    private readonly DatabaseFixture _fixture;

    public HousekeepingTests(DatabaseFixture fixture) => _fixture = fixture;

    private HousekeepingRunner Runner(HousekeepingOptions? options = null)
        => new(new HousekeepingStore(_fixture.RuntimeConnectionFactory), options ?? new HousekeepingOptions(), new RefreshTokenOptions(),
            new FakeTimeProvider(new DateTimeOffset(Now)), NullLogger<HousekeepingRunner>.Instance);

    private async Task<long> CountAsync(string sql, object p)
    {
        await using var c = await _fixture.ConnectionFactory.OpenConnectionAsync();
        return await c.ExecuteScalarAsync<long>(new CommandDefinition(sql, p));
    }

    private async Task<Guid> AccountAsync()
    {
        var id = Guid.NewGuid();
        await using var c = await _fixture.ConnectionFactory.OpenConnectionAsync();
        await c.ExecuteAsync(
            "INSERT INTO accounts (id, email, normalized_email, created_at, updated_at) VALUES (@id, @e, @n, @now, @now);",
            new { id, e = $"hk-{id:N}@example.com", n = $"HK-{id:N}@EXAMPLE.COM", now = Now.AddDays(-400) });
        return id;
    }

    private async Task<Guid> ChallengeAsync(Guid accountId, DateTime expiresAt, bool withOutbox = false)
    {
        var id = Guid.NewGuid();
        await using var c = await _fixture.ConnectionFactory.OpenConnectionAsync();
        await c.ExecuteAsync(
            """
            INSERT INTO email_verification_challenges (id, account_id, purpose, token_hash, created_at, expires_at, consumed_at, invalidated_at, attempt_count)
            VALUES (@id, @accountId, 'email_verification', @hash, @created, @expiresAt, NULL, NULL, 0);
            """, new { id, accountId, hash = RandomNumberGenerator.GetBytes(32), created = expiresAt.AddMinutes(-30), expiresAt });
        if (withOutbox)
        {
            await c.ExecuteAsync(
                """
                INSERT INTO email_outbox (id, challenge_id, message_type, recipient_email, payload_version, created_at, available_at, attempt_count, failed_at)
                VALUES (@oid, @id, 'email_verification', 'x@example.com', 1, @created, @created, 0, @created);
                """, new { oid = Guid.NewGuid(), id, created = expiresAt });
        }

        return id;
    }

    private async Task<Guid> MfaAsync(Guid accountId, DateTime expiresAt)
    {
        var id = Guid.NewGuid();
        await using var c = await _fixture.ConnectionFactory.OpenConnectionAsync();
        await c.ExecuteAsync(
            """
            INSERT INTO mfa_challenges (id, account_id, token_hash, password_hash_fingerprint, user_agent, created_at, expires_at, consumed_at, attempt_count)
            VALUES (@id, @accountId, @t, @f, NULL, @created, @expiresAt, NULL, 0);
            """, new { id, accountId, t = RandomNumberGenerator.GetBytes(32), f = RandomNumberGenerator.GetBytes(32), created = expiresAt.AddMinutes(-5), expiresAt });
        return id;
    }

    private async Task<Guid> SessionAsync(Guid accountId, DateTime lastSeen, DateTime absolute, DateTime? revoked)
    {
        var id = Guid.NewGuid();
        await using var c = await _fixture.ConnectionFactory.OpenConnectionAsync();
        await c.ExecuteAsync(
            """
            INSERT INTO sessions (id, account_id, created_at, last_seen_at, absolute_expires_at, revoked_at, user_agent)
            VALUES (@id, @accountId, @created, @lastSeen, @absolute, @revoked, 'ua');
            """, new { id, accountId, created = absolute.AddDays(-90), lastSeen, absolute, revoked });
        for (var i = 0; i < 3; i++)
        {
            await c.ExecuteAsync(
                """
                INSERT INTO refresh_tokens (id, session_id, token_hash, created_at, expires_at, consumed_at, revoked_at, replaced_by_token_id)
                VALUES (@tid, @id, @hash, @lastSeen, @lastSeen, NULL, NULL, NULL);
                """, new { tid = Guid.NewGuid(), id, hash = RandomNumberGenerator.GetBytes(32), lastSeen });
        }

        return id;
    }

    [Fact]
    public async Task Run_DeletesOnlyRowsDeadLongerThanTheRetention_WithTheirChildren()
    {
        var a = await AccountAsync();
        var oldChallenge = await ChallengeAsync(a, Now.AddDays(-31), withOutbox: true);
        var recentChallenge = await ChallengeAsync(a, Now.AddDays(-29));
        var liveChallenge = await ChallengeAsync(a, Now.AddMinutes(10));
        var oldMfa = await MfaAsync(a, Now.AddDays(-31));
        var recentMfa = await MfaAsync(a, Now.AddDays(-1));

        var revokedLongAgo = await SessionAsync(a, Now.AddDays(-40), Now.AddDays(50), revoked: Now.AddDays(-31));
        var absoluteExpired = await SessionAsync(a, Now.AddDays(-35), Now.AddDays(-31), revoked: null);
        var idleExpired = await SessionAsync(a, Now.AddDays(-61), Now.AddDays(20), revoked: null); // idle 30 d ended 31 d ago
        var revokedRecently = await SessionAsync(a, Now.AddDays(-2), Now.AddDays(50), revoked: Now.AddDays(-1));
        var idleRecently = await SessionAsync(a, Now.AddDays(-45), Now.AddDays(20), revoked: null);       // idle ended 15 d ago
        var live = await SessionAsync(a, Now.AddMinutes(-5), Now.AddDays(80), revoked: null);

        var result = await Runner().RunOnceAsync();

        Assert.True(result.EmailChallenges >= 1);
        Assert.True(result.MfaChallenges >= 1);
        Assert.True(result.Sessions >= 3);
        Assert.Equal(0L, await CountAsync("SELECT COUNT(*) FROM email_verification_challenges WHERE id=@oldChallenge", new { oldChallenge }));
        Assert.Equal(0L, await CountAsync("SELECT COUNT(*) FROM email_outbox WHERE challenge_id=@oldChallenge", new { oldChallenge }));
        Assert.Equal(2L, await CountAsync("SELECT COUNT(*) FROM email_verification_challenges WHERE id IN (@recentChallenge, @liveChallenge)", new { recentChallenge, liveChallenge }));
        Assert.Equal(0L, await CountAsync("SELECT COUNT(*) FROM mfa_challenges WHERE id=@oldMfa", new { oldMfa }));
        Assert.Equal(1L, await CountAsync("SELECT COUNT(*) FROM mfa_challenges WHERE id=@recentMfa", new { recentMfa }));

        var dead = new[] { revokedLongAgo, absoluteExpired, idleExpired };
        var kept = new[] { revokedRecently, idleRecently, live };
        Assert.Equal(0L, await CountAsync("SELECT COUNT(*) FROM sessions WHERE id IN @dead", new { dead }));
        Assert.Equal(0L, await CountAsync("SELECT COUNT(*) FROM refresh_tokens WHERE session_id IN @dead", new { dead }));
        Assert.Equal(3L, await CountAsync("SELECT COUNT(*) FROM sessions WHERE id IN @kept", new { kept }));
        Assert.Equal(9L, await CountAsync("SELECT COUNT(*) FROM refresh_tokens WHERE session_id IN @kept", new { kept }));
        Assert.Equal(1L, await CountAsync("SELECT COUNT(*) FROM accounts WHERE id=@a", new { a })); // accounts are never pruned
    }

    [Fact]
    public async Task Run_IsBoundedByBatchSizeTimesMaxBatches()
    {
        await Runner().RunOnceAsync(); // clear anything older from other tests first
        var a = await AccountAsync();
        for (var i = 0; i < 5; i++)
        {
            await ChallengeAsync(a, Now.AddDays(-40 - i));
        }

        var result = await Runner(new HousekeepingOptions { BatchSize = 2, MaxBatchesPerRun = 2 }).RunOnceAsync();

        Assert.Equal(4, result.EmailChallenges);
        Assert.Equal(1L, await CountAsync("SELECT COUNT(*) FROM email_verification_challenges WHERE account_id=@a", new { a }));
        Assert.Equal(1, (await Runner().RunOnceAsync()).EmailChallenges); // the next run finishes the job
    }

    [Fact]
    public void Composition_ValidatesOptions_AndRegistersTheHostedServiceOnlyWhenEnabled()
    {
        static IConfiguration Cfg(Dictionary<string, string?> d) => new ConfigurationBuilder().AddInMemoryCollection(d).Build();
        const string conn = "Server=127.0.0.1;Database=x;User ID=x;Password=y";

        var on = new ServiceCollection();
        on.AddBitosxHousekeeping(Cfg(new()), conn);
        Assert.Contains(on, d => d.ServiceType == typeof(IHostedService));

        var off = new ServiceCollection();
        off.AddBitosxHousekeeping(Cfg(new() { ["Housekeeping:Enabled"] = "false" }), conn);
        Assert.DoesNotContain(off, d => d.ServiceType == typeof(IHostedService));

        Assert.Throws<InvalidOperationException>(() => new ServiceCollection().AddBitosxHousekeeping(Cfg(new() { ["Housekeeping:RetentionDays"] = "0" }), conn));
        Assert.Throws<InvalidOperationException>(() => new ServiceCollection().AddBitosxHousekeeping(Cfg(new() { ["Housekeeping:BatchSize"] = "0" }), conn));
        Assert.Throws<InvalidOperationException>(() => new ServiceCollection().AddBitosxHousekeeping(Cfg(new() { ["Housekeeping:IntervalMinutes"] = "0" }), conn));
        Assert.Throws<InvalidOperationException>(() => new ServiceCollection().AddBitosxHousekeeping(Cfg(new() { ["Housekeeping:MaxBatchesPerRun"] = "1001" }), conn));
    }
}
