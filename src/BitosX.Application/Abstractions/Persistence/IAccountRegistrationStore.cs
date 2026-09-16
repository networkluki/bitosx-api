using BitosX.Application.Accounts;
using BitosX.Application.Email;
using BitosX.Application.Verification;

namespace BitosX.Application.Abstractions.Persistence;

public enum RegistrationOutcome
{
    Created,
    EmailAlreadyExists,
}

/// <summary>
/// Creates a new unverified account together with its first verification
/// challenge and outbox message, atomically. The account is created with a NULL
/// password hash — the password is set later at verification.
/// </summary>
public interface IAccountRegistrationStore
{
    Task<RegistrationOutcome> CreateUnverifiedAccountWithChallengeAndOutboxAsync(
        Account account,
        EmailVerificationChallenge challenge,
        EmailOutboxMessage outbox,
        CancellationToken cancellationToken = default);
}
