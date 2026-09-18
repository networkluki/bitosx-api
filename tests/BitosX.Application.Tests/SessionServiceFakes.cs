using BitosX.Application.Abstractions.Persistence;
using BitosX.Application.Security;

namespace BitosX.Application.Tests;

/// <summary>Configurable password hasher with counters + trace. Verify does NOT run real Argon2.</summary>
internal sealed class ConfigurablePasswordHasher : IAccountPasswordHasher
{
    public PasswordVerificationResult VerifyResult { get; set; } = PasswordVerificationResult.Success;
    public int HashCalls { get; private set; }
    public int VerifyCalls { get; private set; }
    public string? LastVerifyPassword { get; private set; }
    public string? LastVerifyHash { get; private set; }
    public List<string>? Trace { get; set; }

    public Task<string> HashAsync(string password, CancellationToken cancellationToken = default) { HashCalls++; return Task.FromResult("$argon2id$v=19$m=8192,t=1,p=1$c2FsdA$aGFzaA"); }

    public Task<PasswordVerificationResult> VerifyAsync(string password, string encodedHash, CancellationToken cancellationToken = default)
    {
        VerifyCalls++;
        LastVerifyPassword = password;
        LastVerifyHash = encodedHash;
        Trace?.Add("verify");
        return Task.FromResult(VerifyResult);
    }
}

/// <summary>Configurable refresh-token factory (generation + strict-parse) with counters + trace.</summary>
internal sealed class FakeRefreshTokenFactory : IRefreshTokenFactory
{
    public string NextToken { get; set; } = "generated-refresh-token-plaintext";
    public byte[] NextVerifier { get; set; } = Enumerable.Repeat((byte)0xAA, 32).ToArray();
    public bool TryResult { get; set; } = true;
    public byte[] PresentedVerifier { get; set; } = Enumerable.Repeat((byte)0xBB, 32).ToArray();
    public int GenerateCalls { get; private set; }
    public int TryCalls { get; private set; }
    public string? LastPresentedToken { get; private set; }
    public List<string>? Trace { get; set; }

    public GeneratedRefreshToken Generate()
    {
        GenerateCalls++;
        Trace?.Add("generate");
        return new GeneratedRefreshToken(NextToken, NextVerifier);
    }

    public bool TryComputeVerifier(string presentedTokenBase64Url, out byte[] verifier)
    {
        TryCalls++;
        LastPresentedToken = presentedTokenBase64Url;
        Trace?.Add("try");
        if (TryResult) { verifier = PresentedVerifier; return true; }
        verifier = [];
        return false;
    }
}

/// <summary>Configurable access-token issuer with counters, captures, trace, and optional throw.</summary>
internal sealed class FakeAccessTokenService : IAccessTokenService
{
    public AccessToken TokenToReturn { get; set; } = new("access-jwt-string", new DateTime(2026, 9, 17, 12, 15, 0, DateTimeKind.Utc), Guid.NewGuid());
    public Exception? Throws { get; set; }
    public int IssueCalls { get; private set; }
    public Guid LastAccountId { get; private set; }
    public Guid LastSessionId { get; private set; }
    public DateTime LastNowUtc { get; private set; }
    public List<string>? Trace { get; set; }

    public AccessToken Issue(Guid accountId, Guid sessionId, DateTime nowUtc)
    {
        IssueCalls++;
        Trace?.Add("issue");
        LastAccountId = accountId;
        LastSessionId = sessionId;
        LastNowUtc = nowUtc;
        if (Throws is not null) throw Throws;
        return TokenToReturn;
    }
}

/// <summary>In-memory ISessionStore fake: snapshots received verifier arrays at call time.</summary>
internal sealed class FakeSessionStore : ISessionStore
{
    public LoginSessionCreateResult CreateResult { get; set; } = new() { Outcome = LoginSessionCreateOutcome.Created };
    public RefreshRotationResult RotateResult { get; set; } = new() { Outcome = RefreshRotationOutcome.Rotated };
    public Exception? CreateThrows { get; set; }
    public Exception? RotateThrows { get; set; }

    public int CreateCalls { get; private set; }
    public int RotateCalls { get; private set; }
    public Guid LastAccountId { get; private set; }
    public string? LastNormalizedEmail { get; private set; }
    public string? LastExpectedPasswordHash { get; private set; }
    public string? LastUserAgent { get; private set; }
    public byte[]? CapturedInitialVerifier { get; private set; }
    public byte[]? CapturedPresentedVerifier { get; private set; }
    public byte[]? CapturedNextVerifier { get; private set; }
    public List<string>? Trace { get; set; }

    public Task<LoginSessionCreateResult> CreateOnLoginAsync(LoginSessionCreateRequest request, CancellationToken cancellationToken = default)
    {
        CreateCalls++;
        Trace?.Add("create");
        cancellationToken.ThrowIfCancellationRequested();
        LastAccountId = request.AccountId;
        LastNormalizedEmail = request.NormalizedEmail;
        LastExpectedPasswordHash = request.ExpectedPasswordHash;
        LastUserAgent = request.UserAgent;
        CapturedInitialVerifier = (byte[])request.InitialRefreshVerifier.Clone(); // snapshot before caller zeroes
        if (CreateThrows is not null) throw CreateThrows;
        return Task.FromResult(CreateResult);
    }

    public Task<RefreshRotationResult> RotateAsync(RefreshRotationRequest request, CancellationToken cancellationToken = default)
    {
        RotateCalls++;
        Trace?.Add("rotate");
        cancellationToken.ThrowIfCancellationRequested();
        CapturedPresentedVerifier = (byte[])request.PresentedVerifier.Clone();
        CapturedNextVerifier = (byte[])request.NextVerifier.Clone();
        if (RotateThrows is not null) throw RotateThrows;
        return Task.FromResult(RotateResult);
    }

    public SessionAuthState? AuthState { get; set; }
    public Exception? AuthStateThrows { get; set; }
    public int GetAuthStateCalls { get; private set; }
    public Guid LastAuthStateSessionId { get; private set; }

    public Task<SessionAuthState?> GetSessionAuthStateAsync(Guid sessionId, CancellationToken cancellationToken = default)
    {
        GetAuthStateCalls++;
        LastAuthStateSessionId = sessionId;
        cancellationToken.ThrowIfCancellationRequested();
        if (AuthStateThrows is not null) throw AuthStateThrows;
        return Task.FromResult(AuthState);
    }

    public SessionDeleteOutcome DeleteResult { get; set; } = SessionDeleteOutcome.Deleted;
    public IReadOnlyList<SessionListRow> ListResult { get; set; } = [];
    public int LogoutCalls { get; private set; }
    public int LogoutAllCalls { get; private set; }
    public int DeleteCalls { get; private set; }
    public int ListCalls { get; private set; }
    public Guid LastLogoutAccountId { get; private set; }
    public Guid LastLogoutSessionId { get; private set; }
    public Guid LastLogoutAllAccountId { get; private set; }
    public Guid LastDeleteAccountId { get; private set; }
    public Guid LastDeleteSessionId { get; private set; }
    public Guid LastListAccountId { get; private set; }

    public Task LogoutAsync(Guid accountId, Guid sessionId, CancellationToken cancellationToken = default)
    {
        LogoutCalls++; LastLogoutAccountId = accountId; LastLogoutSessionId = sessionId;
        cancellationToken.ThrowIfCancellationRequested();
        return Task.CompletedTask;
    }

    public Task LogoutAllAsync(Guid accountId, CancellationToken cancellationToken = default)
    {
        LogoutAllCalls++; LastLogoutAllAccountId = accountId;
        cancellationToken.ThrowIfCancellationRequested();
        return Task.CompletedTask;
    }

    public Task<SessionDeleteOutcome> DeleteSessionAsync(Guid accountId, Guid sessionId, CancellationToken cancellationToken = default)
    {
        DeleteCalls++; LastDeleteAccountId = accountId; LastDeleteSessionId = sessionId;
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(DeleteResult);
    }

    public Task<IReadOnlyList<SessionListRow>> ListSessionsAsync(Guid accountId, CancellationToken cancellationToken = default)
    {
        ListCalls++; LastListAccountId = accountId;
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(ListResult);
    }
}
