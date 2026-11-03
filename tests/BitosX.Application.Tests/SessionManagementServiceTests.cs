using BitosX.Application.Abstractions.Persistence;
using BitosX.Application.Security;
using BitosX.Application.Sessions;

namespace BitosX.Application.Tests;

public sealed class SessionManagementServiceTests
{
    private static readonly DateTime Now = new(2026, 9, 18, 12, 0, 0, DateTimeKind.Utc);
    private static readonly Guid Account = Guid.Parse("cccccccc-cccc-cccc-cccc-cccccccccccc");
    private static readonly Guid Current = Guid.Parse("dddddddd-dddd-dddd-dddd-dddddddddddd");
    private static readonly RefreshTokenOptions Options = new(); // IdleLifetime 30d

    private static (SessionManagementService svc, FakeSessionStore store) Build()
    {
        var store = new FakeSessionStore();
        return (new SessionManagementService(store, Options), store);
    }

    [Fact]
    public async Task Logout_ForwardsAccountAndCurrentSession()
    {
        var (svc, store) = Build();
        await svc.LogoutAsync(Account, Current);
        Assert.Equal(1, store.LogoutCalls);
        Assert.Equal(Account, store.LastLogoutAccountId);
        Assert.Equal(Current, store.LastLogoutSessionId);
    }

    [Fact]
    public async Task LogoutAll_ForwardsAccount()
    {
        var (svc, store) = Build();
        await svc.LogoutAllAsync(Account);
        Assert.Equal(1, store.LogoutAllCalls);
        Assert.Equal(Account, store.LastLogoutAllAccountId);
    }

    [Fact]
    public async Task Delete_OwnedDeleted_MapsToSucceeded()
    {
        var (svc, store) = Build();
        store.DeleteResult = SessionDeleteOutcome.Deleted;
        var target = Guid.NewGuid();
        var result = await svc.DeleteSessionAsync(Account, Current, target);
        Assert.Equal(DeleteSessionResult.Succeeded, result);
        Assert.Equal(Account, store.LastDeleteAccountId);
        Assert.Equal(target, store.LastDeleteSessionId);
    }

    [Fact]
    public async Task Delete_StoreNotFound_MapsToNotFound()
    {
        var (svc, store) = Build();
        store.DeleteResult = SessionDeleteOutcome.NotFound;
        Assert.Equal(DeleteSessionResult.NotFound, await svc.DeleteSessionAsync(Account, Current, Guid.NewGuid()));
    }

    [Fact]
    public async Task List_MapsRows_WithEffectiveExpiry_AndCurrentFlag_AndNoUserAgentField()
    {
        var (svc, store) = Build();
        var other = Guid.NewGuid();
        store.ListResult =
        [
            // absolute far out, idle window nearer → ExpiresAt = lastSeen + 30d
            new SessionListRow(Current, Now.AddDays(-1), Now.AddDays(-1), Now.AddDays(89)),
            // absolute nearer than idle window → ExpiresAt = absolute
            new SessionListRow(other, Now.AddDays(-40), Now.AddDays(-5), Now.AddDays(2)),
        ];

        var items = await svc.ListSessionsAsync(Account, Current);

        Assert.Equal(2, items.Count);
        Assert.Equal(Now.AddDays(-1).AddDays(30), items[0].ExpiresAt); // min(absolute now+89d, lastSeen+30d) = lastSeen+30d
        Assert.True(items[0].Current);
        Assert.Equal(Now.AddDays(2), items[1].ExpiresAt);              // min(absolute now+2d, lastSeen+30d) = absolute
        Assert.False(items[1].Current);
        Assert.Equal(Account, store.LastListAccountId);

        // The DTO type exposes no user-agent / account-id / secret members.
        var members = typeof(SessionListItem).GetProperties().Select(p => p.Name).ToArray();
        foreach (var forbidden in new[] { "UserAgent", "AccountId", "TokenHash", "RefreshToken", "Email" })
        {
            Assert.DoesNotContain(forbidden, members);
        }
    }

    [Fact]
    public async Task List_NeverReturnsMoreThan200_EvenIfTheStoreDoes()
    {
        var (svc, store) = Build();
        store.ListResult = Enumerable.Range(0, 250)
            .Select(i => new SessionListRow(Guid.NewGuid(), Now.AddMinutes(-i), Now, Now.AddDays(1)))
            .ToList();

        var items = await svc.ListSessionsAsync(Account, Current);

        Assert.Equal(SessionListLimits.MaxListedSessions, items.Count);
        Assert.Equal(Now, items[0].CreatedAt); // the store's order (newest first) is kept
    }

    [Fact]
    public async Task Cancellation_Propagates_ForEachOperation()
    {
        var (svc, _) = Build();
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => svc.LogoutAsync(Account, Current, cts.Token));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => svc.LogoutAllAsync(Account, cts.Token));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => svc.ListSessionsAsync(Account, Current, cts.Token));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => svc.DeleteSessionAsync(Account, Current, Guid.NewGuid(), cts.Token));
    }
}
