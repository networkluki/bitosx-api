using BitosX.Application.Abstractions.Persistence;

namespace BitosX.Application.Mfa;

/// <summary>
/// A second-factor code that matched a confirmed enrollment but is not used up yet: either a TOTP step
/// (still to be recorded by the replay guard) or a recovery-code verifier (still to be marked used).
/// </summary>
public sealed record MatchedSecondFactor(bool IsTotp, long Step, byte[]? RecoveryVerifier)
{
    public override string ToString() => $"MatchedSecondFactor {{ IsTotp = {IsTotp}, Step = {Step}, RecoveryVerifier = <redacted> }}";
}

/// <summary>
/// Checks a second-factor code against a confirmed enrollment and consumes it: a TOTP code is matched
/// within the window and its step recorded (replay guard), a recovery code is matched by keyed verifier
/// and marked used. Shared by the second sign-in step and by TOTP management (disable, regenerate) and the
/// password-confirmed account operations. Every failure is one boolean; nothing says which kind of code was
/// tried. Matching and consuming are also available separately, so the second sign-in step can claim its
/// challenge before it uses up a code.
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
        var match = await TryMatchAsync(enrollment, code, cancellationToken).ConfigureAwait(false);
        return match is not null && await ConsumeAsync(enrollment, match, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Whether <paramref name="code"/> is a valid, unused TOTP or recovery code for the confirmed enrollment.
    /// Consumes nothing; <see cref="ConsumeAsync"/> is the authority on single use.
    /// </summary>
    public async Task<MatchedSecondFactor?> TryMatchAsync(TotpEnrollment enrollment, string? code, CancellationToken cancellationToken = default)
    {
        if (enrollment is null || !enrollment.IsConfirmed || string.IsNullOrEmpty(code) || code.Length > 32)
        {
            return null;
        }

        var trimmed = code.Trim();
        if (Rfc6238Totp.IsDigits(trimmed, _options.Digits))
        {
            return TryMatchTotp(enrollment, trimmed, out var step) ? new MatchedSecondFactor(true, step, null) : null;
        }

        var canonical = RecoveryCodes.Canonicalize(trimmed);
        if (canonical is null)
        {
            return null;
        }

        var verifier = _crypto.RecoveryCodeVerifier(canonical);
        return await _store.HasUnusedRecoveryCodeAsync(enrollment.AccountId, verifier, cancellationToken).ConfigureAwait(false)
            ? new MatchedSecondFactor(false, 0, verifier)
            : null;
    }

    /// <summary>
    /// Uses up a matched code. The store decides: two concurrent presentations of the same TOTP step or the same
    /// recovery code race here, and exactly one wins.
    /// </summary>
    public Task<bool> ConsumeAsync(TotpEnrollment enrollment, MatchedSecondFactor match, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(enrollment);
        ArgumentNullException.ThrowIfNull(match);
        return match.IsTotp
            ? _store.TryConsumeStepAsync(enrollment.AccountId, match.Step, cancellationToken)
            : _store.TryConsumeRecoveryCodeAsync(enrollment.AccountId, match.RecoveryVerifier!, _clock.GetUtcNow().UtcDateTime, cancellationToken);
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
}
