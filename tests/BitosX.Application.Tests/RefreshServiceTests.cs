using BitosX.Application.Abstractions.Persistence;
using BitosX.Application.Security;
using BitosX.Application.Sessions;

namespace BitosX.Application.Tests;

public sealed class RefreshServiceTests
{
    private static readonly DateTime RotatedAt = new(2026, 9, 17, 13, 0, 0, DateTimeKind.Utc);
    private static readonly DateTime NextExpiresAt = RotatedAt.AddDays(30);
    private static readonly Guid AccountId = Guid.Parse("33333333-3333-3333-3333-333333333333");
    private static readonly Guid SessionId = Guid.Parse("44444444-4444-4444-4444-444444444444");

    private sealed class Harness
    {
        public required RefreshService Service { get; init; }
        public required FakeRefreshTokenFactory Refresh { get; init; }
        public required FakeSessionStore Store { get; init; }
        public required FakeAccessTokenService Access { get; init; }
        public required List<string> Trace { get; init; }
    }

    private static Harness Build()
    {
        var trace = new List<string>();
        var refresh = new FakeRefreshTokenFactory { Trace = trace };
        var store = new FakeSessionStore
        {
            Trace = trace,
            RotateResult = new RefreshRotationResult
            {
                Outcome = RefreshRotationOutcome.Rotated,
                AccountId = AccountId,
                SessionId = SessionId,
                RotatedAt = RotatedAt,
                NextRefreshExpiresAt = NextExpiresAt,
            },
        };
        var access = new FakeAccessTokenService { Trace = trace, TokenToReturn = new AccessToken("NEW.ACCESS.JWT", RotatedAt.AddMinutes(15), Guid.NewGuid()) };
        return new Harness
        {
            Service = new RefreshService(refresh, store, access),
            Refresh = refresh, Store = store, Access = access, Trace = trace,
        };
    }

    private static RefreshCommand Cmd(string token = "presented-refresh-token") => new(token);

    // ---- parser ----

    [Fact]
    public async Task MalformedToken_InvalidRefresh_NoGenerateNoStoreNoJwt()
    {
        var h = Build();
        h.Refresh.TryResult = false;
        var result = await h.Service.RefreshAsync(Cmd());
        Assert.Equal(RefreshOutcome.InvalidRefresh, result.Outcome);
        Assert.Equal(0, h.Refresh.GenerateCalls);
        Assert.Equal(0, h.Store.RotateCalls);
        Assert.Equal(0, h.Access.IssueCalls);
    }

    // ---- rotation ----

    [Fact]
    public async Task Store_ReceivesExactPresentedAndNextVerifier_NotPlaintextToken()
    {
        var h = Build();
        var presentedOriginal = (byte[])h.Refresh.PresentedVerifier.Clone();
        var nextOriginal = (byte[])h.Refresh.NextVerifier.Clone();
        await h.Service.RefreshAsync(Cmd());
        Assert.Equal(presentedOriginal, h.Store.CapturedPresentedVerifier);
        Assert.Equal(nextOriginal, h.Store.CapturedNextVerifier);
    }

    [Fact]
    public async Task StoreInvalid_InvalidRefresh_NoJwt()
    {
        var h = Build();
        h.Store.RotateResult = RefreshRotationResult.Invalid;
        var result = await h.Service.RefreshAsync(Cmd());
        Assert.Equal(RefreshOutcome.InvalidRefresh, result.Outcome);
        Assert.Equal(0, h.Access.IssueCalls);
    }

    [Fact]
    public async Task StoreReuseDetected_CollapsesToSameInvalidRefresh_NoJwt()
    {
        var h = Build();
        h.Store.RotateResult = RefreshRotationResult.ReuseDetected;
        var result = await h.Service.RefreshAsync(Cmd());
        Assert.Equal(RefreshOutcome.InvalidRefresh, result.Outcome); // indistinguishable from Invalid
        Assert.Null(result.RefreshToken);                            // unused successor not returned
        Assert.Equal(0, h.Access.IssueCalls);
    }

    [Fact]
    public async Task StoreThrows_Propagates()
    {
        var h = Build();
        h.Store.RotateThrows = new InvalidOperationException("db down");
        await Assert.ThrowsAsync<InvalidOperationException>(() => h.Service.RefreshAsync(Cmd()));
        Assert.Equal(0, h.Access.IssueCalls);
    }

    [Fact]
    public async Task Cancellation_Propagates()
    {
        var h = Build();
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => h.Service.RefreshAsync(Cmd(), cts.Token));
    }

    // ---- success ----

    [Fact]
    public async Task Rotated_MintsJwt_WithStoreIdentityAndTimestamp_AndSuccessorToken()
    {
        var h = Build();
        var result = await h.Service.RefreshAsync(Cmd());
        Assert.Equal(RefreshOutcome.Succeeded, result.Outcome);
        Assert.Equal(1, h.Access.IssueCalls);
        Assert.Equal(AccountId, h.Access.LastAccountId);
        Assert.Equal(SessionId, h.Access.LastSessionId);
        Assert.Equal(RotatedAt, h.Access.LastNowUtc);              // uses rotation's authoritative time
        Assert.Equal("NEW.ACCESS.JWT", result.AccessToken);
        Assert.Equal(h.Refresh.NextToken, result.RefreshToken);    // successor plaintext returned
        Assert.Equal(NextExpiresAt, result.RefreshTokenExpiresAt);
    }

    [Fact]
    public async Task CallOrder_TryThenGenerateThenRotateThenIssue()
    {
        var h = Build();
        await h.Service.RefreshAsync(Cmd());
        Assert.Equal(new[] { "try", "generate", "rotate", "issue" }, h.Trace);
    }

    [Fact]
    public async Task JwtIssuanceThrowsAfterCommit_Propagates()
    {
        var h = Build();
        h.Access.Throws = new InvalidOperationException("jwt boom");
        await Assert.ThrowsAsync<InvalidOperationException>(() => h.Service.RefreshAsync(Cmd()));
        Assert.Equal(1, h.Store.RotateCalls); // rotation committed; no undo
    }

    // ---- memory ----

    [Fact]
    public async Task Verifiers_ZeroedAfterSuccess()
    {
        var h = Build();
        await h.Service.RefreshAsync(Cmd());
        Assert.All(h.Refresh.PresentedVerifier, b => Assert.Equal(0, b));
        Assert.All(h.Refresh.NextVerifier, b => Assert.Equal(0, b));
    }

    [Fact]
    public async Task Verifiers_ZeroedAfterInvalid()
    {
        var h = Build();
        h.Store.RotateResult = RefreshRotationResult.Invalid;
        await h.Service.RefreshAsync(Cmd());
        Assert.All(h.Refresh.PresentedVerifier, b => Assert.Equal(0, b));
        Assert.All(h.Refresh.NextVerifier, b => Assert.Equal(0, b));
    }

    [Fact]
    public async Task Verifiers_ZeroedAfterReuseDetected()
    {
        var h = Build();
        h.Store.RotateResult = RefreshRotationResult.ReuseDetected;
        await h.Service.RefreshAsync(Cmd());
        Assert.All(h.Refresh.PresentedVerifier, b => Assert.Equal(0, b));
        Assert.All(h.Refresh.NextVerifier, b => Assert.Equal(0, b));
    }

    [Fact]
    public async Task Verifiers_ZeroedAfterException()
    {
        var h = Build();
        h.Store.RotateThrows = new InvalidOperationException("db down");
        await Assert.ThrowsAsync<InvalidOperationException>(() => h.Service.RefreshAsync(Cmd()));
        Assert.All(h.Refresh.PresentedVerifier, b => Assert.Equal(0, b));
        Assert.All(h.Refresh.NextVerifier, b => Assert.Equal(0, b));
    }

    // ---- redaction ----

    [Fact]
    public void RefreshResult_ToString_RedactsBothTokens()
    {
        var s = RefreshResult.Succeeded("HEADER.PAYLOAD.SIG", RotatedAt, "successor-refresh-secret", NextExpiresAt).ToString();
        Assert.DoesNotContain("HEADER.PAYLOAD.SIG", s, StringComparison.Ordinal);
        Assert.DoesNotContain("successor-refresh-secret", s, StringComparison.Ordinal);
        Assert.Contains("<redacted>", s, StringComparison.Ordinal);
    }

    [Fact]
    public void RefreshCommand_ToString_RedactsToken()
    {
        var s = new RefreshCommand("secret-refresh-token").ToString();
        Assert.DoesNotContain("secret-refresh-token", s, StringComparison.Ordinal);
        Assert.Contains("<redacted>", s, StringComparison.Ordinal);
    }
}
