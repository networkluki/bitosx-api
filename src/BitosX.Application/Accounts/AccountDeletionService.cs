using BitosX.Application.Abstractions.Persistence;
using BitosX.Application.Security;

namespace BitosX.Application.Accounts;

/// <summary>The account id comes from the validated session, never from the request body.</summary>
public sealed record DeleteAccountCommand(Guid AccountId, string Password);

public enum DeleteAccountResult
{
    Deleted,

    /// <summary>Wrong password, or an account that cannot be deleted this way (missing/unverified/disabled/changed).</summary>
    InvalidPassword,
}

public interface IAccountDeletionService
{
    Task<DeleteAccountResult> DeleteAsync(DeleteAccountCommand command, CancellationToken cancellationToken = default);
}

/// <summary>
/// Permanent account deletion behind a password confirmation. Bounds the password, reads the account,
/// refuses without Argon2 when the account cannot sign in, verifies the password OUTSIDE any lock, then
/// asks the store to delete under the account lock while re-checking the exact PHC it verified. Every
/// failure collapses to <see cref="DeleteAccountResult.InvalidPassword"/>. Deleting the account removes
/// the stored vault envelope too; a local vault file on the user's device is untouched.
/// </summary>
public sealed class AccountDeletionService : IAccountDeletionService
{
    private readonly IAccountRepository _accounts;
    private readonly IAccountPasswordHasher _passwordHasher;
    private readonly IAccountDeletionStore _store;

    public AccountDeletionService(IAccountRepository accounts, IAccountPasswordHasher passwordHasher, IAccountDeletionStore store)
    {
        _accounts = accounts;
        _passwordHasher = passwordHasher;
        _store = store;
    }

    public async Task<DeleteAccountResult> DeleteAsync(DeleteAccountCommand command, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(command);

        if (command.AccountId == Guid.Empty
            || string.IsNullOrEmpty(command.Password)
            || command.Password.Length > AccountPasswordPolicy.MaxLength)
        {
            return DeleteAccountResult.InvalidPassword;
        }

        var account = await _accounts.GetByIdAsync(command.AccountId, cancellationToken).ConfigureAwait(false);
        if (account is null
            || account.EmailVerifiedAt is null
            || account.PasswordHash is null
            || account.DisabledAt is not null)
        {
            return DeleteAccountResult.InvalidPassword; // no Argon2 for an account that cannot sign in
        }

        var verification = await _passwordHasher.VerifyAsync(command.Password, account.PasswordHash, cancellationToken).ConfigureAwait(false);
        if (verification is PasswordVerificationResult.Failed or PasswordVerificationResult.InvalidHashFormat)
        {
            return DeleteAccountResult.InvalidPassword;
        }

        var outcome = await _store.DeleteAccountAsync(account.Id, account.PasswordHash, cancellationToken).ConfigureAwait(false);
        return outcome == AccountDeleteOutcome.Deleted ? DeleteAccountResult.Deleted : DeleteAccountResult.InvalidPassword;
    }
}
