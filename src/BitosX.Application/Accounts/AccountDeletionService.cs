using BitosX.Application.Abstractions.Persistence;
using BitosX.Application.Mfa;
using BitosX.Application.Security;

namespace BitosX.Application.Accounts;

/// <summary>
/// The account id comes from the validated session, never from the request body. <see cref="Code"/> (a TOTP
/// or recovery code) is required when the account has TOTP confirmed.
/// </summary>
public sealed record DeleteAccountCommand(Guid AccountId, string Password, string? Code = null)
{
    public override string ToString() => $"DeleteAccountCommand {{ AccountId = {AccountId}, Password = <redacted>, Code = <redacted> }}";
}

public enum DeleteAccountResult
{
    Deleted,

    /// <summary>
    /// Wrong password, a missing/wrong second-factor code when TOTP is confirmed, or an account that cannot be
    /// deleted this way (missing/unverified/disabled/changed).
    /// </summary>
    InvalidPassword,

    /// <summary>The account has TOTP confirmed but the server cannot verify codes right now; nothing is deleted.</summary>
    SecondFactorUnavailable,
}

public interface IAccountDeletionService
{
    Task<DeleteAccountResult> DeleteAsync(DeleteAccountCommand command, CancellationToken cancellationToken = default);
}

/// <summary>
/// Permanent account deletion behind a password confirmation. Bounds the password, reads the account,
/// refuses without Argon2 when the account cannot sign in, verifies the password OUTSIDE any lock, then —
/// when the account has TOTP confirmed — a TOTP or recovery code (the same confirmation that turning TOTP off
/// needs), then asks the store to delete under the account lock while re-checking the exact PHC it verified.
/// Every confirmation failure collapses to <see cref="DeleteAccountResult.InvalidPassword"/>. Deleting the account removes
/// the stored vault envelope too; a local vault file on the user's device is untouched.
/// </summary>
public sealed class AccountDeletionService : IAccountDeletionService
{
    private readonly IAccountRepository _accounts;
    private readonly IAccountPasswordHasher _passwordHasher;
    private readonly IAccountDeletionStore _store;
    private readonly ISecondFactorConfirmation _secondFactor;

    public AccountDeletionService(
        IAccountRepository accounts, IAccountPasswordHasher passwordHasher, IAccountDeletionStore store, ISecondFactorConfirmation secondFactor)
    {
        _accounts = accounts;
        _passwordHasher = passwordHasher;
        _store = store;
        _secondFactor = secondFactor;
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

        // Password first, then the code: a wrong password never uses up a TOTP step or a recovery code.
        switch (await _secondFactor.CheckAsync(account.Id, command.Code, cancellationToken).ConfigureAwait(false))
        {
            case SecondFactorCheck.Rejected:
                return DeleteAccountResult.InvalidPassword;
            case SecondFactorCheck.Unavailable:
                return DeleteAccountResult.SecondFactorUnavailable;
        }

        var outcome = await _store.DeleteAccountAsync(account.Id, account.PasswordHash, cancellationToken).ConfigureAwait(false);
        return outcome == AccountDeleteOutcome.Deleted ? DeleteAccountResult.Deleted : DeleteAccountResult.InvalidPassword;
    }
}
