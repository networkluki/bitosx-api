using BitosX.Application.Abstractions.Persistence;
using BitosX.Application.Security;
using BitosX.Application.Sessions;
using Microsoft.Extensions.Time.Testing;

namespace BitosX.Application.Tests;

public sealed class SessionAuthenticatorTests
{
    private static readonly DateTime Now = new(2026, 9, 18, 12, 0, 0, DateTimeKind.Utc);
    private static readonly Guid Account = Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");
    private static readonly Guid Session = Guid.Parse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb");
    private static readonly RefreshTokenOptions Options = new(); // IdleLifetime 30d, AbsoluteLifetime 90d

    private static (SessionAuthenticator auth, FakeSessionStore store) Build(SessionAuthState? state)
    {
        var store = new FakeSessionStore { AuthState = state };
        var clock = new FakeTimeProvider(new DateTimeOffset(Now, TimeSpan.Zero));
        return (new SessionAuthenticator(store, clock, Options), store);
    }

    private static SessionAuthState State(
        Guid? accountId = null, Guid? sessionId = null, DateTime? lastSeenAt = null,
        DateTime? absoluteExpiresAt = null, DateTime? revokedAt = null, DateTime? disabledAt = null)
        => new(sessionId ?? Session, accountId ?? Account, lastSeenAt ?? Now.AddDays(-1), absoluteExpiresAt ?? Now.AddDays(80), revokedAt, disabledAt);

    private static Task<SessionAuthResult> Auth(SessionAuthenticator a) => a.AuthenticateAsync(Account, Session);

    [Fact]
    public async Task ValidState_MatchingAccountAndSession_Valid()
    {
        var (auth, store) = Build(State());
        Assert.Equal(SessionAuthResult.Valid, await Auth(auth));
        Assert.Equal(1, store.GetAuthStateCalls);
        Assert.Equal(Session, store.LastAuthStateSessionId);
    }

    [Fact]
    public async Task MissingState_Invalid()
    {
        var (auth, _) = Build(null);
        Assert.Equal(SessionAuthResult.Invalid, await Auth(auth));
    }

    [Fact]
    public async Task AccountIdMismatch_Invalid()
    {
        var (auth, _) = Build(State(accountId: Guid.NewGuid())); // authoritative owner != claimed Account
        Assert.Equal(SessionAuthResult.Invalid, await Auth(auth));
    }

    [Fact]
    public async Task SessionIdMismatch_Invalid()
    {
        var (auth, _) = Build(State(sessionId: Guid.NewGuid()));
        Assert.Equal(SessionAuthResult.Invalid, await Auth(auth));
    }

    [Fact]
    public async Task RevokedSession_Invalid()
    {
        var (auth, _) = Build(State(revokedAt: Now.AddMinutes(-1)));
        Assert.Equal(SessionAuthResult.Invalid, await Auth(auth));
    }

    [Fact]
    public async Task DisabledAccount_Invalid()
    {
        var (auth, _) = Build(State(disabledAt: Now.AddMinutes(-1)));
        Assert.Equal(SessionAuthResult.Invalid, await Auth(auth));
    }

    [Fact]
    public async Task AbsoluteExpiryPast_Invalid()
    {
        var (auth, _) = Build(State(absoluteExpiresAt: Now.AddMinutes(-1)));
        Assert.Equal(SessionAuthResult.Invalid, await Auth(auth));
    }

    [Fact]
    public async Task AbsoluteExpiryExactlyNow_Invalid()
    {
        var (auth, _) = Build(State(absoluteExpiresAt: Now));
        Assert.Equal(SessionAuthResult.Invalid, await Auth(auth));
    }

    [Fact]
    public async Task IdleAgeOverLimit_Invalid()
    {
        var (auth, _) = Build(State(lastSeenAt: Now.AddDays(-31)));
        Assert.Equal(SessionAuthResult.Invalid, await Auth(auth));
    }

    [Fact]
    public async Task IdleAgeExactlyLimit_Invalid()
    {
        var (auth, _) = Build(State(lastSeenAt: Now.AddDays(-30))); // exactly IdleLifetime → invalid
        Assert.Equal(SessionAuthResult.Invalid, await Auth(auth));
    }

    [Fact]
    public async Task IdleAgeJustBelowLimit_Valid()
    {
        var (auth, _) = Build(State(lastSeenAt: Now.AddDays(-30).AddSeconds(1)));
        Assert.Equal(SessionAuthResult.Valid, await Auth(auth));
    }

    [Fact]
    public async Task Cancellation_Propagates()
    {
        var (auth, _) = Build(State());
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => auth.AuthenticateAsync(Account, Session, cts.Token));
    }
}
