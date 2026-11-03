namespace BitosX.Application.Abstractions.Persistence;

/// <summary>Coarse by design: <see cref="InvalidAccountState"/> covers a missing/unverified/disabled account and a changed hash.</summary>
public enum PasswordChangeOutcome
{
    Changed,
    InvalidAccountState,
}

/// <summary>
/// Replaces the password of a signed-in account. The caller has ALREADY verified the current password
/// (Argon2) and hashed the new one, both outside any lock; no plaintext password reaches the store.
/// </summary>
public interface IAccountPasswordStore
{
    /// <summary>
    /// In one transaction, in the canonical lock order accounts → email_verification_challenges → sessions →
    /// refresh_tokens: lock the account and re-check that it can sign in and still holds exactly
    /// <paramref name="expectedPasswordHash"/>; store <paramref name="newPasswordHash"/>; invalidate every open
    /// password-reset link; revoke every session except <paramref name="keepSessionId"/>, with its refresh tokens.
    /// </summary>
    Task<PasswordChangeOutcome> ChangePasswordAsync(
        Guid accountId, Guid keepSessionId, string expectedPasswordHash, string newPasswordHash, CancellationToken cancellationToken = default);
}
