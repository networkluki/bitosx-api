using BitosX.Application.Security;
using BitosX.Infrastructure.Persistence;
using Dapper;
using Microsoft.Extensions.Time.Testing;

namespace BitosX.Infrastructure.Tests;

/// <summary>Real-MariaDB tests for the read-only per-request session auth-state lookup.</summary>
[Collection("Persistence")]
public sealed class SessionStoreAuthLookupTests
{
    private static readonly DateTime Now = new(2026, 9, 18, 12, 0, 0, DateTimeKind.Utc);
    private const string Phc = "$argon2id$v=19$m=8192,t=1,p=1$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYQ";

    private readonly DatabaseFixture _fixture;
    public SessionStoreAuthLookupTests(DatabaseFixture fixture) => _fixture = fixture;

    private SessionStore Store() => new(_fixture.RuntimeConnectionFactory, new FakeTimeProvider(new DateTimeOffset(Now, TimeSpan.Zero)), new RefreshTokenOptions());

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

    private async Task<Guid> SeedSessionAsync(Guid accountId, DateTime lastSeen, DateTime absolute, DateTime? revokedAt = null)
    {
        var id = Guid.NewGuid();
        await using var c = await _fixture.ConnectionFactory.OpenConnectionAsync();
        await c.ExecuteAsync(
            """
            INSERT INTO sessions (id, account_id, created_at, last_seen_at, absolute_expires_at, revoked_at, user_agent)
            VALUES (@id, @accountId, @now, @lastSeen, @absolute, @revokedAt, 'secret-user-agent');
            """,
            new { id, accountId, now = Now, lastSeen, absolute, revokedAt });
        return id;
    }

    [Fact]
    public async Task Missing_ReturnsNull()
        => Assert.Null(await Store().GetSessionAuthStateAsync(Guid.NewGuid()));

    [Fact]
    public async Task Existing_ReturnsAuthoritativeStateWithNoSecrets()
    {
        var accountId = await SeedAccountAsync();
        var lastSeen = Now.AddDays(-2);
        var absolute = Now.AddDays(88);
        var sessionId = await SeedSessionAsync(accountId, lastSeen, absolute);

        var state = await Store().GetSessionAuthStateAsync(sessionId);
        Assert.NotNull(state);
        Assert.Equal(sessionId, state!.SessionId);
        Assert.Equal(accountId, state.AccountId);         // authoritative owner discovered
        Assert.Equal(lastSeen, state.LastSeenAt);         // round-trips
        Assert.Equal(absolute, state.AbsoluteExpiresAt);  // round-trips
        Assert.Null(state.RevokedAt);
        Assert.Null(state.AccountDisabledAt);

        // The auth-state record type carries no secret/PII members.
        var members = typeof(BitosX.Application.Abstractions.Persistence.SessionAuthState)
            .GetProperties().Select(p => p.Name).ToArray();
        foreach (var forbidden in new[] { "Email", "PasswordHash", "Phone", "UserAgent", "TokenHash", "RefreshToken" })
        {
            Assert.DoesNotContain(forbidden, members);
        }
    }

    [Fact]
    public async Task RevokedSession_RevokedAtObservable()
    {
        var accountId = await SeedAccountAsync();
        var sessionId = await SeedSessionAsync(accountId, Now.AddDays(-1), Now.AddDays(89), revokedAt: Now.AddMinutes(-5));
        var state = await Store().GetSessionAuthStateAsync(sessionId);
        Assert.NotNull(state!.RevokedAt);
    }

    [Fact]
    public async Task DisabledAccount_DisabledAtObservable()
    {
        var accountId = await SeedAccountAsync(disabled: true);
        var sessionId = await SeedSessionAsync(accountId, Now.AddDays(-1), Now.AddDays(89));
        var state = await Store().GetSessionAuthStateAsync(sessionId);
        Assert.NotNull(state!.AccountDisabledAt);
    }
}
