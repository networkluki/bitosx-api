using BitosX.Application.Abstractions.Persistence;
using BitosX.Application.Mfa;
using BitosX.Application.Security;

namespace BitosX.Application.Accounts;

/// <summary>The account and the session come from the validated JWT, never from the request body.</summary>
public sealed record ChangePasswordCommand(Guid AccountId, Guid SessionId, string CurrentPassword, string NewPassword, string? Code)
{
    public override string ToString()
        => $"ChangePasswordCommand {{ AccountId = {AccountId}, SessionId = {SessionId}, CurrentPassword = <redacted>, NewPassword = <redacted>, Code = <redacted> }}";
}

public enum ChangePasswordResult
{
    /// <summary>The password was replaced; every other session is revoked, the caller's stays valid.</summary>
    Changed,

    /// <summary>The new password is outside the account-password policy (12–128 characters).</summary>
    InvalidNewPassword,

    /// <summary>Wrong current password, missing/wrong second-factor code, or an account that cannot sign in.</summary>
    ConfirmationFailed,

    /// <summary>The account has TOTP confirmed but the server cannot verify codes right now.</summary>
    SecondFactorUnavailable,
}

public interface IPasswordChangeService
{
    Task<ChangePasswordResult> ChangeAsync(ChangePasswordCommand command, CancellationToken cancellationToken = default);
}

/// <summary>
/// Change the account password while signed in. Checks the new password against policy first (no Argon2
/// for a request that can never succeed), refuses without Argon2 when the account cannot sign in, verifies
/// the current password (Argon2, outside any lock), then the second factor when TOTP is confirmed, hashes
/// the new password (Argon2, outside any lock) and lets the store swap the hash under the account lock while
/// re-checking the exact hash it verified. Every confirmation failure collapses to
/// <see cref="ChangePasswordResult.ConfirmationFailed"/>. The vault master password is not affected: the
/// server never has it.
/// </summary>
public sealed class PasswordChangeService : IPasswordChangeService
{
    private readonly IAccountRepository _accounts;
    private readonly IAccountPasswordHasher _passwordHasher;
    private readonly ISecondFactorConfirmation _secondFactor;
    private readonly IAccountPasswordStore _store;

    public PasswordChangeService(
        IAccountRepository accounts, IAccountPasswordHasher passwordHasher, ISecondFactorConfirmation secondFactor, IAccountPasswordStore store)
    {
        _accounts = accounts;
        _passwordHasher = passwordHasher;
        _secondFactor = secondFactor;
        _store = store;
    }

    public async Task<ChangePasswordResult> ChangeAsync(ChangePasswordCommand command, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(command);

        if (AccountPasswordPolicy.Validate(command.NewPassword) != PasswordPolicyResult.Valid)
        {
            return ChangePasswordResult.InvalidNewPassword;
        }

        if (command.AccountId == Guid.Empty
            || command.SessionId == Guid.Empty
            || string.IsNullOrEmpty(command.CurrentPassword)
            || command.CurrentPassword.Length > AccountPasswordPolicy.MaxLength)
        {
            return ChangePasswordResult.ConfirmationFailed;
        }

        var account = await _accounts.GetByIdAsync(command.AccountId, cancellationToken).ConfigureAwait(false);
        if (account is null
            || account.EmailVerifiedAt is null
            || account.PasswordHash is null
            || account.DisabledAt is not null)
        {
            return ChangePasswordResult.ConfirmationFailed; // no Argon2 for an account that cannot sign in
        }

        var verification = await _passwordHasher.VerifyAsync(command.CurrentPassword, account.PasswordHash, cancellationToken).ConfigureAwait(false);
        if (verification is PasswordVerificationResult.Failed or PasswordVerificationResult.InvalidHashFormat)
        {
            return ChangePasswordResult.ConfirmationFailed;
        }

        // Password first, then the code: a wrong password never uses up a TOTP step or a recovery code.
        switch (await _secondFactor.CheckAsync(account.Id, command.Code, cancellationToken).ConfigureAwait(false))
        {
            case SecondFactorCheck.Rejected:
                return ChangePasswordResult.ConfirmationFailed;
            case SecondFactorCheck.Unavailable:
                return ChangePasswordResult.SecondFactorUnavailable;
        }

        var newHash = await _passwordHasher.HashAsync(command.NewPassword, cancellationToken).ConfigureAwait(false);

        var outcome = await _store.ChangePasswordAsync(account.Id, command.SessionId, account.PasswordHash, newHash, cancellationToken).ConfigureAwait(false);
        return outcome == PasswordChangeOutcome.Changed ? ChangePasswordResult.Changed : ChangePasswordResult.ConfirmationFailed;
    }
}
