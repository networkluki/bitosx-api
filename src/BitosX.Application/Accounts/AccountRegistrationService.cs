using BitosX.Application.Abstractions.Persistence;
using BitosX.Application.Verification;

namespace BitosX.Application.Accounts;

public sealed record RegisterCommand(string Email);

public enum RegistrationResult
{
    Accepted,
    InvalidEmail,
}

public interface IAccountRegistrationService
{
    Task<RegistrationResult> RegisterAsync(RegisterCommand command, CancellationToken cancellationToken = default);
}

/// <summary>
/// Email-first registration: accepts only an email and creates an unverified
/// account with a NULL password hash. The password is chosen later at
/// verification. No password is accepted or hashed here. Responses are generic
/// (always Accepted) for both new and existing addresses to resist enumeration.
/// </summary>
public sealed class AccountRegistrationService : IAccountRegistrationService
{
    private readonly IAccountRepository _accounts;
    private readonly IAccountRegistrationStore _registrationStore;
    private readonly IVerificationChallengeFactory _challengeFactory;
    private readonly TimeProvider _clock;

    public AccountRegistrationService(
        IAccountRepository accounts,
        IAccountRegistrationStore registrationStore,
        IVerificationChallengeFactory challengeFactory,
        TimeProvider clock)
    {
        _accounts = accounts;
        _registrationStore = registrationStore;
        _challengeFactory = challengeFactory;
        _clock = clock;
    }

    public async Task<RegistrationResult> RegisterAsync(RegisterCommand command, CancellationToken cancellationToken = default)
    {
        if (!EmailAddressValidator.IsValid(command.Email))
        {
            return RegistrationResult.InvalidEmail;
        }

        var normalized = EmailNormalizer.Normalize(command.Email);

        var existing = await _accounts.GetByNormalizedEmailAsync(normalized, cancellationToken).ConfigureAwait(false);
        if (existing is not null)
        {
            // Existing account (verified or not): create nothing, send nothing.
            return RegistrationResult.Accepted;
        }

        var now = _clock.GetUtcNow().UtcDateTime;
        var accountId = Guid.NewGuid();
        var prepared = _challengeFactory.Create(accountId, command.Email, now);

        var account = new Account
        {
            Id = accountId,
            Email = command.Email,
            NormalizedEmail = normalized,
            CreatedAt = now,
            UpdatedAt = now,
        };

        // Outcome (Created or EmailAlreadyExists on a race) maps to the same generic result.
        await _registrationStore.CreateUnverifiedAccountWithChallengeAndOutboxAsync(
            account, prepared.Challenge, prepared.Outbox, cancellationToken).ConfigureAwait(false);

        return RegistrationResult.Accepted;
    }
}
