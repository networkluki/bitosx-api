using BitosX.Application.Accounts;
using BitosX.Application.Verification;
using Microsoft.Extensions.Time.Testing;

namespace BitosX.Application.Tests;

public sealed class AccountRegistrationServiceTests
{
    private readonly FakeAccountRepository _accounts = new();
    private readonly FakeRegistrationStore _store = new();
    private readonly SpyPasswordHasher _hasher = new();
    private readonly FakeTimeProvider _clock = new(DateTimeOffset.Parse("2026-09-16T12:00:00Z"));

    private AccountRegistrationService Service()
    {
        var factory = new VerificationChallengeFactory(new FakeTokenFactory(), new FakeOutboxPayloadProtector(),
            new EmailVerificationSecurityOptions { Pepper = "x" });
        return new AccountRegistrationService(_accounts, _store, factory, _clock);
    }

    [Fact]
    public async Task Register_InvalidEmail_ReturnsInvalidEmail_NoStoreCall()
    {
        var result = await Service().RegisterAsync(new RegisterCommand("not-an-email"));
        Assert.Equal(RegistrationResult.InvalidEmail, result);
        Assert.Equal(0, _store.Calls);
    }

    [Fact]
    public async Task Register_NewEmail_CreatesUnverifiedAccount_NullPassword_NoHashing()
    {
        var result = await Service().RegisterAsync(new RegisterCommand("New.User@Example.com"));

        Assert.Equal(RegistrationResult.Accepted, result);
        Assert.Equal(1, _store.Calls);
        Assert.NotNull(_store.LastAccount);
        Assert.Null(_store.LastAccount!.PasswordHash);             // password not set at registration
        Assert.Null(_store.LastAccount.EmailVerifiedAt);
        Assert.Equal("NEW.USER@EXAMPLE.COM", _store.LastAccount.NormalizedEmail);
        Assert.Equal(0, _hasher.HashCalls);                        // register never hashes
    }

    [Fact]
    public async Task Register_ExistingEmail_IsGenericAccepted_NoStoreCall()
    {
        _accounts.Seed(new Account
        {
            Id = Guid.NewGuid(), Email = "taken@example.com", NormalizedEmail = "TAKEN@EXAMPLE.COM",
            EmailVerifiedAt = _clock.GetUtcNow().UtcDateTime, // verified
            CreatedAt = _clock.GetUtcNow().UtcDateTime, UpdatedAt = _clock.GetUtcNow().UtcDateTime,
        });

        var result = await Service().RegisterAsync(new RegisterCommand("taken@example.com"));

        Assert.Equal(RegistrationResult.Accepted, result);
        Assert.Equal(0, _store.Calls);
        Assert.Equal(0, _hasher.HashCalls);
    }
}
