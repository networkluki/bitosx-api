using BitosX.Application.Abstractions.Persistence;

namespace BitosX.Application.Mfa;

/// <summary>
/// Checks a second-factor code against a confirmed enrollment and consumes it: a TOTP code is matched
/// within the window and its step recorded (replay guard), a recovery code is matched by keyed verifier
/// and marked used. Shared by the second sign-in step and by TOTP management (disable, regenerate).
/// Every failure is one boolean; nothing says which kind of code was tried.
/// </summary>
public sealed class MfaCodeVerifier
{
    private readonly ITotpStore _store;
    private readonly ITotpCrypto _crypto;
    private readonly TotpOptions _options;
    private readonly TimeProvider _clock;

    public MfaCodeVerifier(ITotpStore store, ITotpCrypto crypto, TotpOptions options, TimeProvider clock)
    {
        _store = store;
        _crypto = crypto;
        _options = options;
        _clock = clock;
    }

    public async Task<bool> VerifyAndConsumeAsync(TotpEnrollment enrollment, string? code, CancellationToken cancellationToken = default)
    {
        if (enrollment is null || !enrollment.IsConfirmed || string.IsNullOrEmpty(code) || code.Length > 32)
        {
            return false;
        }

        var trimmed = code.Trim();
        if (Rfc6238Totp.IsDigits(trimmed, _options.Digits))
        {
            return await VerifyTotpAsync(enrollment, trimmed, cancellationToken).ConfigureAwait(false);
        }

        var canonical = RecoveryCodes.Canonicalize(trimmed);
        if (canonical is null)
        {
            return false;
        }

        var verifier = _crypto.RecoveryCodeVerifier(canonical);
        return await _store.TryConsumeRecoveryCodeAsync(enrollment.AccountId, verifier, _clock.GetUtcNow().UtcDateTime, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>TOTP only (used to confirm a pending enrollment, where no recovery codes exist yet). Does not consume.</summary>
    public bool TryMatchTotp(TotpEnrollment enrollment, string? code, out long matchedStep)
    {
        matchedStep = 0;
        if (enrollment is null || string.IsNullOrEmpty(code)) return false;
        if (!_crypto.TryUnprotect(enrollment.Secret, enrollment.AccountId, out var secret)) return false;
        try
        {
            return Rfc6238Totp.TryMatch(
                secret, code.Trim(), _clock.GetUtcNow().ToUnixTimeSeconds(), _options.Digits, _options.PeriodSeconds,
                _options.WindowSteps, enrollment.LastUsedStep, out matchedStep);
        }
        finally
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(secret);
        }
    }

    private async Task<bool> VerifyTotpAsync(TotpEnrollment enrollment, string code, CancellationToken cancellationToken)
    {
        if (!TryMatchTotp(enrollment, code, out var step))
        {
            return false;
        }

        // The store is the authority on replay: two concurrent presentations of the same code race here,
        // and exactly one wins.
        return await _store.TryConsumeStepAsync(enrollment.AccountId, step, cancellationToken).ConfigureAwait(false);
    }
}
