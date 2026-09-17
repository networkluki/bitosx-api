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

    public string Hash(string password) { HashCalls++; return "$argon2id$v=19$m=8192,t=1,p=1$c2FsdA$aGFzaA"; }

    public PasswordVerificationResult Verify(string password, string encodedHash)
    {
        VerifyCalls++;
        LastVerifyPassword = password;
        LastVerifyHash = encodedHash;
        Trace?.Add("verify");
        return VerifyResult;
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
}
