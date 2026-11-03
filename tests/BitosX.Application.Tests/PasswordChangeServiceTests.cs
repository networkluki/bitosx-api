using BitosX.Application.Abstractions.Persistence;
using BitosX.Application.Accounts;
using BitosX.Application.Mfa;
using BitosX.Application.Security;

namespace BitosX.Application.Tests;

public sealed class PasswordChangeServiceTests
{
    private const string Phc = "$argon2id$v=19$m=8192,t=1,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYQ";
    private const string Current = "Correct-Horse-Battery-Staple-1";
    private const string Next = "Another-Long-Password-2";

    private readonly FakeAccountRepository _accounts = new();
    private readonly TracingHasher _hasher = new();
    private readonly FakeSecondFactor _secondFactor = new();
    private readonly FakeAccountPasswordStore _store = new();
    private readonly List<string> _trace = [];

    public PasswordChangeServiceTests()
    {
        _hasher.Trace = _trace;
        _secondFactor.Trace = _trace;
    }

    private PasswordChangeService Service() => new(_accounts, _hasher, _secondFactor, _store);

    private Account Seed(bool verified = true, bool disabled = false, string? hash = Phc)
    {
        var account = new Account
        {
            Id = Guid.NewGuid(), Email = "u@example.com", NormalizedEmail = "U@EXAMPLE.COM",
            EmailVerifiedAt = verified ? DateTime.UtcNow : null, PasswordHash = hash,
            DisabledAt = disabled ? DateTime.UtcNow : null, CreatedAt = DateTime.UtcNow, UpdatedAt = DateTime.UtcNow,
        };
        _accounts.Seed(account);
        return account;
    }

    private static ChangePasswordCommand Command(Account a, string current = Current, string next = Next, string? code = null, Guid? session = null)
        => new(a.Id, session ?? Guid.Parse("11111111-2222-4333-8444-555555555555"), current, next, code);

    [Fact]
    public async Task CorrectPassword_VerifiesThenHashes_AndKeepsTheCallingSession()
    {
        var account = Seed();
        var session = Guid.NewGuid();

        var result = await Service().ChangeAsync(Command(account, session: session));

        Assert.Equal(ChangePasswordResult.Changed, result);
        Assert.Equal(["verify", "code", "hash"], _trace); // password first, then the second factor, then Argon2 for the new hash
        Assert.Equal(account.Id, _store.LastAccountId);
        Assert.Equal(session, _store.LastKeepSessionId);
        Assert.Equal(Phc, _store.LastExpectedHash);          // the exact PHC that was verified
        Assert.Equal(TracingHasher.NewPhc, _store.LastNewHash);
        Assert.Equal(Next, _hasher.LastHashed);              // used exactly as typed
    }

    [Theory]
    [InlineData("short")]
    [InlineData("")]
    public async Task NewPasswordOutsidePolicy_Is400_WithoutAnyArgon2(string next)
    {
        var account = Seed();
        Assert.Equal(ChangePasswordResult.InvalidNewPassword, await Service().ChangeAsync(Command(account, next: next)));
        Assert.Empty(_trace);
        Assert.Equal(0, _store.Calls);
    }

    [Fact]
    public async Task NewPasswordTooLong_Is400()
    {
        var account = Seed();
        Assert.Equal(ChangePasswordResult.InvalidNewPassword, await Service().ChangeAsync(Command(account, next: new string('x', 129))));
        Assert.Equal(ChangePasswordResult.Changed, await Service().ChangeAsync(Command(account, next: new string('x', 128))));
    }

    [Fact]
    public async Task WrongCurrentPassword_IsTheGenericFailure_AndNeverTouchesTheCode()
    {
        var account = Seed();
        _hasher.VerifyResult = PasswordVerificationResult.Failed;
        _secondFactor.Result = SecondFactorCheck.Accepted;

        Assert.Equal(ChangePasswordResult.ConfirmationFailed, await Service().ChangeAsync(Command(account, code: "123456")));
        Assert.Equal(["verify"], _trace);
        Assert.Equal(0, _store.Calls);
    }

    [Theory]
    [InlineData(false, false, Phc)]
    [InlineData(true, true, Phc)]
    [InlineData(true, false, null)]
    public async Task AccountThatCannotSignIn_IsRefusedWithoutArgon2(bool verified, bool disabled, string? hash)
    {
        var account = Seed(verified, disabled, hash);
        Assert.Equal(ChangePasswordResult.ConfirmationFailed, await Service().ChangeAsync(Command(account)));
        Assert.Empty(_trace);
    }

    [Fact]
    public async Task UnknownAccount_OrOverlongCurrentPassword_IsRefusedWithoutArgon2()
    {
        var ghost = new Account { Id = Guid.NewGuid(), Email = "x@example.com", NormalizedEmail = "X@EXAMPLE.COM" };
        Assert.Equal(ChangePasswordResult.ConfirmationFailed, await Service().ChangeAsync(Command(ghost)));
        var account = Seed();
        Assert.Equal(ChangePasswordResult.ConfirmationFailed, await Service().ChangeAsync(Command(account, current: new string('x', 129))));
        Assert.Equal(ChangePasswordResult.ConfirmationFailed, await Service().ChangeAsync(Command(account, current: "")));
        Assert.Empty(_trace);
    }

    [Fact]
    public async Task TotpConfirmed_WrongOrMissingCode_IsTheGenericFailure()
    {
        var account = Seed();
        _secondFactor.Result = SecondFactorCheck.Rejected;

        Assert.Equal(ChangePasswordResult.ConfirmationFailed, await Service().ChangeAsync(Command(account)));
        Assert.Equal(0, _store.Calls);
        Assert.Equal(0, _hasher.HashCalls);
    }

    [Fact]
    public async Task TotpConfirmed_ButUnverifiable_FailsClosed()
    {
        var account = Seed();
        _secondFactor.Result = SecondFactorCheck.Unavailable;

        Assert.Equal(ChangePasswordResult.SecondFactorUnavailable, await Service().ChangeAsync(Command(account, code: "123456")));
        Assert.Equal(0, _store.Calls);
    }

    [Fact]
    public async Task HashChangedMeanwhile_IsTheGenericFailure()
    {
        var account = Seed();
        _store.Outcome = PasswordChangeOutcome.InvalidAccountState;
        Assert.Equal(ChangePasswordResult.ConfirmationFailed, await Service().ChangeAsync(Command(account)));
    }

    [Fact]
    public async Task CapacityExceeded_Propagates()
    {
        var account = Seed();
        _hasher.Throw = true;
        await Assert.ThrowsAsync<PasswordHashingCapacityExceededException>(() => Service().ChangeAsync(Command(account)));
        Assert.Equal(0, _store.Calls);
    }

    [Fact]
    public void Command_ToString_RedactsSecrets()
    {
        var text = new ChangePasswordCommand(Guid.NewGuid(), Guid.NewGuid(), "old-secret-password", "new-secret-password", "123456").ToString();
        Assert.DoesNotContain("old-secret-password", text);
        Assert.DoesNotContain("new-secret-password", text);
        Assert.DoesNotContain("123456", text);
    }

    private sealed class TracingHasher : IAccountPasswordHasher
    {
        public const string NewPhc = "$argon2id$v=19$m=8192,t=1,p=1$bmV3c2FsdA$bmV3aGFzaG5ld2hhc2huZXdoYXNo";
        public List<string>? Trace { get; set; }
        public PasswordVerificationResult VerifyResult { get; set; } = PasswordVerificationResult.Success;
        public bool Throw { get; set; }
        public int HashCalls { get; private set; }
        public string? LastHashed { get; private set; }

        public Task<string> HashAsync(string password, CancellationToken cancellationToken = default)
        {
            if (Throw) throw new PasswordHashingCapacityExceededException();
            HashCalls++; LastHashed = password; Trace?.Add("hash");
            return Task.FromResult(NewPhc);
        }

        public Task<PasswordVerificationResult> VerifyAsync(string password, string encodedHash, CancellationToken cancellationToken = default)
        {
            if (Throw) throw new PasswordHashingCapacityExceededException();
            Trace?.Add("verify");
            return Task.FromResult(VerifyResult);
        }
    }
}
