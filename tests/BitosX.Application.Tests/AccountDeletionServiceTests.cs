using BitosX.Application.Abstractions.Persistence;
using BitosX.Application.Accounts;
using BitosX.Application.Security;

namespace BitosX.Application.Tests;

public sealed class AccountDeletionServiceTests
{
    private const string Phc = "$argon2id$v=19$m=8192,t=1,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYQ";
    private const string Pw = "Correct-Horse-Battery-Staple-1";

    private readonly FakeAccountRepository _accounts = new();
    private readonly ConfigurablePasswordHasher _hasher = new();
    private readonly FakeAccountDeletionStore _store = new();

    private AccountDeletionService Service() => new(_accounts, _hasher, _store);

    private Account Verified() => new()
    {
        Id = Guid.NewGuid(), Email = "u@example.com", NormalizedEmail = "U@EXAMPLE.COM",
        EmailVerifiedAt = DateTime.UtcNow, PasswordHash = Phc, CreatedAt = DateTime.UtcNow, UpdatedAt = DateTime.UtcNow,
    };

    [Fact]
    public async Task CorrectPassword_DeletesWithExactVerifiedHash()
    {
        var account = Verified();
        _accounts.Seed(account);
        _hasher.VerifyResult = PasswordVerificationResult.Success;

        var r = await Service().DeleteAsync(new DeleteAccountCommand(account.Id, Pw));

        Assert.Equal(DeleteAccountResult.Deleted, r);
        Assert.Equal(1, _hasher.VerifyCalls);
        Assert.Equal(1, _store.Calls);
        Assert.Equal(account.Id, _store.LastAccountId);
        Assert.Equal(Phc, _store.LastExpectedHash);
    }

    [Fact]
    public async Task NeedsRehash_StillCountsAsCorrectPassword()
    {
        var account = Verified();
        _accounts.Seed(account);
        _hasher.VerifyResult = PasswordVerificationResult.NeedsRehash;

        Assert.Equal(DeleteAccountResult.Deleted, await Service().DeleteAsync(new DeleteAccountCommand(account.Id, Pw)));
    }

    [Theory]
    [InlineData(PasswordVerificationResult.Failed)]
    [InlineData(PasswordVerificationResult.InvalidHashFormat)]
    public async Task WrongPassword_NoDelete(PasswordVerificationResult verification)
    {
        var account = Verified();
        _accounts.Seed(account);
        _hasher.VerifyResult = verification;

        Assert.Equal(DeleteAccountResult.InvalidPassword, await Service().DeleteAsync(new DeleteAccountCommand(account.Id, "wrong-password-123")));
        Assert.Equal(0, _store.Calls);
    }

    [Fact]
    public async Task EmptyOrOversizedPassword_NoArgon2_NoDelete()
    {
        var account = Verified();
        _accounts.Seed(account);

        Assert.Equal(DeleteAccountResult.InvalidPassword, await Service().DeleteAsync(new DeleteAccountCommand(account.Id, "")));
        Assert.Equal(DeleteAccountResult.InvalidPassword, await Service().DeleteAsync(new DeleteAccountCommand(account.Id, new string('x', AccountPasswordPolicy.MaxLength + 1))));
        Assert.Equal(0, _hasher.VerifyCalls);
        Assert.Equal(0, _store.Calls);
    }

    [Fact]
    public async Task UnknownUnverifiedOrDisabledAccount_NoArgon2_NoDelete()
    {
        var unverified = Verified() with { EmailVerifiedAt = null, PasswordHash = null };
        var disabled = Verified() with { DisabledAt = DateTime.UtcNow };
        _accounts.Seed(unverified);
        _accounts.Seed(disabled);

        Assert.Equal(DeleteAccountResult.InvalidPassword, await Service().DeleteAsync(new DeleteAccountCommand(Guid.NewGuid(), Pw)));
        Assert.Equal(DeleteAccountResult.InvalidPassword, await Service().DeleteAsync(new DeleteAccountCommand(unverified.Id, Pw)));
        Assert.Equal(DeleteAccountResult.InvalidPassword, await Service().DeleteAsync(new DeleteAccountCommand(disabled.Id, Pw)));
        Assert.Equal(0, _hasher.VerifyCalls);
        Assert.Equal(0, _store.Calls);
    }

    [Fact]
    public async Task StoreStateChanged_CollapsesToInvalidPassword()
    {
        var account = Verified();
        _accounts.Seed(account);
        _hasher.VerifyResult = PasswordVerificationResult.Success;
        _store.Outcome = AccountDeleteOutcome.InvalidAccountState;

        Assert.Equal(DeleteAccountResult.InvalidPassword, await Service().DeleteAsync(new DeleteAccountCommand(account.Id, Pw)));
    }

    [Fact]
    public async Task CapacityExceeded_Propagates()
    {
        var account = Verified();
        _accounts.Seed(account);
        var service = new AccountDeletionService(_accounts, new ThrowingHasher(), _store);

        await Assert.ThrowsAsync<PasswordHashingCapacityExceededException>(() => service.DeleteAsync(new DeleteAccountCommand(account.Id, Pw)));
        Assert.Equal(0, _store.Calls);
    }

    private sealed class ThrowingHasher : IAccountPasswordHasher
    {
        public Task<string> HashAsync(string password, CancellationToken cancellationToken = default) => throw new PasswordHashingCapacityExceededException();
        public Task<PasswordVerificationResult> VerifyAsync(string password, string encodedHash, CancellationToken cancellationToken = default) => throw new PasswordHashingCapacityExceededException();
    }
}
