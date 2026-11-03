using BitosX.Application.Abstractions.Persistence;

namespace BitosX.Application.Mfa;

/// <summary>The answer to "does this operation also need the second factor, and was the code right?".</summary>
public enum SecondFactorCheck
{
    /// <summary>The account has no confirmed TOTP: the password alone confirms the operation.</summary>
    NotRequired,

    /// <summary>TOTP is confirmed and the TOTP or recovery code was valid (and is now used up).</summary>
    Accepted,

    /// <summary>TOTP is confirmed and the code is missing or wrong.</summary>
    Rejected,

    /// <summary>TOTP is confirmed but the server cannot verify codes (the Totp capability is off): fail closed.</summary>
    Unavailable,
}

/// <summary>
/// Second-factor confirmation for password-confirmed account operations (change password, delete account),
/// in addition to the password. Callers check the password FIRST, so a wrong password never consumes a code.
/// </summary>
public interface ISecondFactorConfirmation
{
    Task<SecondFactorCheck> CheckAsync(Guid accountId, string? code, CancellationToken cancellationToken = default);
}

/// <summary>
/// See <see cref="ISecondFactorConfirmation"/>. Composed with Login (it needs only the TOTP store); the code
/// verifier exists only with the Totp capability, and without it an account with TOTP confirmed is refused
/// (<see cref="SecondFactorCheck.Unavailable"/>), never let through on the password alone.
/// </summary>
public sealed class SecondFactorConfirmation : ISecondFactorConfirmation
{
    private readonly ITotpStore _store;
    private readonly MfaCodeVerifier? _codes;

    public SecondFactorConfirmation(ITotpStore store, MfaCodeVerifier? codes)
    {
        _store = store ?? throw new ArgumentNullException(nameof(store));
        _codes = codes;
    }

    public async Task<SecondFactorCheck> CheckAsync(Guid accountId, string? code, CancellationToken cancellationToken = default)
    {
        var enrollment = await _store.GetAsync(accountId, cancellationToken).ConfigureAwait(false);
        if (enrollment is null || !enrollment.IsConfirmed)
        {
            return SecondFactorCheck.NotRequired; // no TOTP, or only a pending (unconfirmed) enrollment
        }

        if (_codes is null)
        {
            return SecondFactorCheck.Unavailable;
        }

        if (string.IsNullOrWhiteSpace(code))
        {
            return SecondFactorCheck.Rejected;
        }

        return await _codes.VerifyAndConsumeAsync(enrollment, code, cancellationToken).ConfigureAwait(false)
            ? SecondFactorCheck.Accepted
            : SecondFactorCheck.Rejected;
    }
}
