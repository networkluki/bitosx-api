using System.Security.Cryptography;
using BitosX.Application.Abstractions.Persistence;
using BitosX.Application.Accounts;
using BitosX.Application.Security;
using BitosX.Application.Sessions;

namespace BitosX.Application.Tests;

public sealed class LoginServiceTests
{
    private const string Phc = "$argon2id$v=19$m=8192,t=1,p=1$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYQ";
    private const string RawEmail = "User@Example.com";
    private const string GoodPassword = "correct horse battery staple";

    private static readonly DateTime SessionCreatedAt = new(2026, 9, 17, 12, 0, 0, DateTimeKind.Utc);
    private static readonly DateTime RefreshExpiresAt = SessionCreatedAt.AddDays(30);
    private static readonly Guid AccountId = Guid.Parse("11111111-1111-1111-1111-111111111111");
    private static readonly Guid SessionId = Guid.Parse("22222222-2222-2222-2222-222222222222");

    private sealed class Harness
    {
        public required LoginService Service { get; init; }
        public required FakeAccountRepository Accounts { get; init; }
        public required ConfigurablePasswordHasher Hasher { get; init; }
        public required FakeRefreshTokenFactory Refresh { get; init; }
        public required FakeSessionStore Store { get; init; }
        public required FakeAccessTokenService Access { get; init; }
        public required List<string> Trace { get; init; }
    }

    private static Harness Build(bool seedAccount = true, bool verified = true, string? passwordHash = Phc, DateTime? disabledAt = null)
    {
        var trace = new List<string>();
        var accounts = new FakeAccountRepository { Trace = trace };
        var hasher = new ConfigurablePasswordHasher { Trace = trace };
        var refresh = new FakeRefreshTokenFactory { Trace = trace };
        var store = new FakeSessionStore
        {
            Trace = trace,
            CreateResult = new LoginSessionCreateResult
            {
                Outcome = LoginSessionCreateOutcome.Created,
                AccountId = AccountId,
                SessionId = SessionId,
                SessionCreatedAt = SessionCreatedAt,
                SessionAbsoluteExpiresAt = SessionCreatedAt.AddDays(90),
                RefreshTokenExpiresAt = RefreshExpiresAt,
            },
        };
        var access = new FakeAccessTokenService { Trace = trace, TokenToReturn = new AccessToken("ACCESS.JWT.VALUE", SessionCreatedAt.AddMinutes(15), Guid.NewGuid()) };

        if (seedAccount)
        {
            accounts.Seed(new Account
            {
                Id = AccountId,
                Email = RawEmail,
                NormalizedEmail = EmailNormalizer.Normalize(RawEmail),
                EmailVerifiedAt = verified ? SessionCreatedAt.AddDays(-1) : (DateTime?)null,
                PasswordHash = passwordHash,
                CreatedAt = SessionCreatedAt.AddDays(-2),
                UpdatedAt = SessionCreatedAt.AddDays(-2),
                DisabledAt = disabledAt,
            });
        }

        return new Harness
        {
            Service = new LoginService(accounts, hasher, refresh, store, access),
            Accounts = accounts, Hasher = hasher, Refresh = refresh, Store = store, Access = access, Trace = trace,
        };
    }

    private static LoginCommand Cmd(string email = RawEmail, string password = GoodPassword, string? ua = null) => new(email, password, ua);

    // ---- input / normalization ----

    [Fact]
    public async Task ValidEmail_NormalizedBeforeLookup()
    {
        var h = Build();
        var result = await h.Service.LoginAsync(Cmd(email: "USER@Example.com"));
        Assert.Equal(LoginOutcome.Succeeded, result.Outcome);
        Assert.Equal(EmailNormalizer.Normalize("USER@Example.com"), h.Accounts.LastNormalizedEmailQueried);
        Assert.Equal(EmailNormalizer.Normalize("USER@Example.com"), h.Store.LastNormalizedEmail);
    }

    [Fact]
    public async Task InvalidEmailFormat_InvalidCredentials_NoArgon2()
    {
        var h = Build();
        var result = await h.Service.LoginAsync(Cmd(email: "not-an-email"));
        Assert.Equal(LoginOutcome.InvalidCredentials, result.Outcome);
        Assert.Equal(0, h.Hasher.VerifyCalls);
    }

    [Fact]
    public async Task OverLimitEmail_InvalidCredentials_BeforeRepoAndArgon2()
    {
        var h = Build();
        var huge = new string('a', 321) + "@example.com";
        var result = await h.Service.LoginAsync(Cmd(email: huge));
        Assert.Equal(LoginOutcome.InvalidCredentials, result.Outcome);
        Assert.Equal(0, h.Accounts.GetByNormalizedEmailCalls);
        Assert.Equal(0, h.Hasher.VerifyCalls);
    }

    [Fact]
    public async Task OverLimitPassword_InvalidCredentials_BeforeArgon2()
    {
        var h = Build();
        var result = await h.Service.LoginAsync(Cmd(password: new string('x', AccountPasswordPolicy.MaxLength + 1)));
        Assert.Equal(LoginOutcome.InvalidCredentials, result.Outcome);
        Assert.Equal(0, h.Hasher.VerifyCalls);
    }

    [Fact]
    public async Task Password_PassedUnchangedToArgon2_NoTrim()
    {
        var h = Build();
        var padded = "  spaced password value  ";
        await h.Service.LoginAsync(Cmd(password: padded));
        Assert.Equal(padded, h.Hasher.LastVerifyPassword);
    }

    // ---- account state (no Argon2) ----

    [Fact]
    public async Task UnknownEmail_InvalidCredentials_NoArgon2()
    {
        var h = Build(seedAccount: false);
        var result = await h.Service.LoginAsync(Cmd());
        Assert.Equal(LoginOutcome.InvalidCredentials, result.Outcome);
        Assert.Equal(0, h.Hasher.VerifyCalls);
    }

    [Fact]
    public async Task UnverifiedAccount_InvalidCredentials_NoArgon2()
    {
        var h = Build(verified: false);
        var result = await h.Service.LoginAsync(Cmd());
        Assert.Equal(LoginOutcome.InvalidCredentials, result.Outcome);
        Assert.Equal(0, h.Hasher.VerifyCalls);
    }

    [Fact]
    public async Task NullPasswordHash_InvalidCredentials_NoArgon2()
    {
        var h = Build(passwordHash: null);
        var result = await h.Service.LoginAsync(Cmd());
        Assert.Equal(LoginOutcome.InvalidCredentials, result.Outcome);
        Assert.Equal(0, h.Hasher.VerifyCalls);
    }

    [Fact]
    public async Task DisabledAccount_InvalidCredentials_NoArgon2()
    {
        var h = Build(disabledAt: SessionCreatedAt.AddDays(-1));
        var result = await h.Service.LoginAsync(Cmd());
        Assert.Equal(LoginOutcome.InvalidCredentials, result.Outcome);
        Assert.Equal(0, h.Hasher.VerifyCalls);
    }

    // ---- password verification ----

    [Fact]
    public async Task Argon2Failed_InvalidCredentials_NoStore()
    {
        var h = Build();
        h.Hasher.VerifyResult = PasswordVerificationResult.Failed;
        var result = await h.Service.LoginAsync(Cmd());
        Assert.Equal(LoginOutcome.InvalidCredentials, result.Outcome);
        Assert.Equal(0, h.Store.CreateCalls);
    }

    [Fact]
    public async Task Argon2InvalidHashFormat_InvalidCredentials_NoStore()
    {
        var h = Build();
        h.Hasher.VerifyResult = PasswordVerificationResult.InvalidHashFormat;
        var result = await h.Service.LoginAsync(Cmd());
        Assert.Equal(LoginOutcome.InvalidCredentials, result.Outcome);
        Assert.Equal(0, h.Store.CreateCalls);
    }

    [Fact]
    public async Task Argon2Success_Continues()
    {
        var h = Build();
        h.Hasher.VerifyResult = PasswordVerificationResult.Success;
        Assert.Equal(LoginOutcome.Succeeded, (await h.Service.LoginAsync(Cmd())).Outcome);
    }

    [Fact]
    public async Task Argon2NeedsRehash_Continues_AndDoesNotRehash()
    {
        var h = Build();
        h.Hasher.VerifyResult = PasswordVerificationResult.NeedsRehash;
        var result = await h.Service.LoginAsync(Cmd());
        Assert.Equal(LoginOutcome.Succeeded, result.Outcome);
        Assert.Equal(0, h.Hasher.HashCalls); // no opportunistic rehash
    }

    // ---- store orchestration ----

    [Fact]
    public async Task Store_ReceivesExactVerifiedPhc_NormalizedEmail_UserAgent_AndVerifierNotPlaintext()
    {
        var h = Build();
        var originalVerifier = (byte[])h.Refresh.NextVerifier.Clone();
        await h.Service.LoginAsync(Cmd(ua: "BitosX-Desktop/1.0"));

        Assert.Equal(Phc, h.Store.LastExpectedPasswordHash);          // exact PHC that Argon2 verified
        Assert.Equal(EmailNormalizer.Normalize(RawEmail), h.Store.LastNormalizedEmail);
        Assert.Equal("BitosX-Desktop/1.0", h.Store.LastUserAgent);
        Assert.Equal(AccountId, h.Store.LastAccountId);
        Assert.Equal(originalVerifier, h.Store.CapturedInitialVerifier); // SHA-256 verifier, not the plaintext token
        Assert.NotEqual(h.Refresh.NextToken, System.Text.Encoding.UTF8.GetString(h.Store.CapturedInitialVerifier!));
    }

    [Fact]
    public async Task StoreInvalidAccountState_InvalidCredentials_NoJwt()
    {
        var h = Build();
        h.Store.CreateResult = LoginSessionCreateResult.InvalidAccountState;
        var result = await h.Service.LoginAsync(Cmd());
        Assert.Equal(LoginOutcome.InvalidCredentials, result.Outcome);
        Assert.Equal(0, h.Access.IssueCalls);
    }

    [Fact]
    public async Task StoreThrows_Propagates()
    {
        var h = Build();
        h.Store.CreateThrows = new InvalidOperationException("db down");
        await Assert.ThrowsAsync<InvalidOperationException>(() => h.Service.LoginAsync(Cmd()));
        Assert.Equal(0, h.Access.IssueCalls);
    }

    [Fact]
    public async Task Cancellation_Propagates()
    {
        var h = Build();
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => h.Service.LoginAsync(Cmd(), cts.Token));
    }

    // ---- token issuance ----

    [Fact]
    public async Task Jwt_IssuedOnlyAfterCreated_WithStoreIdentityAndTimestamp()
    {
        var h = Build();
        var result = await h.Service.LoginAsync(Cmd());
        Assert.Equal(LoginOutcome.Succeeded, result.Outcome);
        Assert.Equal(1, h.Access.IssueCalls);
        Assert.Equal(AccountId, h.Access.LastAccountId);
        Assert.Equal(SessionId, h.Access.LastSessionId);
        Assert.Equal(SessionCreatedAt, h.Access.LastNowUtc);       // uses authoritative store timestamp
        Assert.Equal("ACCESS.JWT.VALUE", result.AccessToken);
        Assert.Equal(h.Refresh.NextToken, result.RefreshToken);    // plaintext refresh propagated
        Assert.Equal(RefreshExpiresAt, result.RefreshTokenExpiresAt); // expiry from store
    }

    [Fact]
    public async Task CallOrder_LookupThenVerifyThenGenerateThenCreateThenIssue()
    {
        var h = Build();
        await h.Service.LoginAsync(Cmd());
        Assert.Equal(new[] { "lookup", "verify", "generate", "create", "issue" }, h.Trace);
    }

    // ---- memory / redaction ----

    [Fact]
    public async Task Verifier_ZeroedAfterSuccess()
    {
        var h = Build();
        await h.Service.LoginAsync(Cmd());
        Assert.All(h.Refresh.NextVerifier, b => Assert.Equal(0, b)); // service zeroed its owned verifier
    }

    [Fact]
    public async Task Verifier_ZeroedAfterInvalidAccountState()
    {
        var h = Build();
        h.Store.CreateResult = LoginSessionCreateResult.InvalidAccountState;
        await h.Service.LoginAsync(Cmd());
        Assert.All(h.Refresh.NextVerifier, b => Assert.Equal(0, b));
    }

    [Fact]
    public async Task Verifier_ZeroedAfterException()
    {
        var h = Build();
        h.Store.CreateThrows = new InvalidOperationException("db down");
        await Assert.ThrowsAsync<InvalidOperationException>(() => h.Service.LoginAsync(Cmd()));
        Assert.All(h.Refresh.NextVerifier, b => Assert.Equal(0, b));
    }

    [Fact]
    public async Task JwtIssuanceThrowsAfterCommit_Propagates_NoUndo()
    {
        var h = Build();
        h.Access.Throws = new InvalidOperationException("jwt boom");
        await Assert.ThrowsAsync<InvalidOperationException>(() => h.Service.LoginAsync(Cmd()));
        Assert.Equal(1, h.Store.CreateCalls);   // session was committed; no attempt to undo
        Assert.All(h.Refresh.NextVerifier, b => Assert.Equal(0, b)); // verifier still zeroed
    }

    [Fact]
    public void LoginResult_ToString_RedactsBothTokens()
    {
        var r = LoginResult.Succeeded("HEADER.PAYLOAD.SIG", SessionCreatedAt, "refresh-secret-token", RefreshExpiresAt);
        var s = r.ToString();
        Assert.DoesNotContain("HEADER.PAYLOAD.SIG", s, StringComparison.Ordinal);
        Assert.DoesNotContain("refresh-secret-token", s, StringComparison.Ordinal);
        Assert.Contains("<redacted>", s, StringComparison.Ordinal);
    }

    [Fact]
    public void LoginCommand_ToString_RedactsPassword()
    {
        var s = new LoginCommand("user@example.com", "super-secret-pw").ToString();
        Assert.DoesNotContain("super-secret-pw", s, StringComparison.Ordinal);
        Assert.Contains("<redacted>", s, StringComparison.Ordinal);
    }
}
