using System.Security.Cryptography;
using BitosX.Application.Abstractions.Persistence;
using BitosX.Application.Accounts;
using BitosX.Application.Security;

namespace BitosX.Application.Mfa;

public enum TotpBeginOutcome { Started, InvalidPassword, AlreadyEnabled }

public sealed record TotpBeginResult(TotpBeginOutcome Outcome, string? SecretBase32 = null, string? OtpauthUri = null, string? Issuer = null, string? Label = null)
{
    public override string ToString() => $"TotpBeginResult {{ Outcome = {Outcome}, Secret = <redacted> }}";
}

public enum TotpConfirmResult { Confirmed, InvalidCode, NotPending }

public sealed record TotpConfirmation(TotpConfirmResult Outcome, IReadOnlyList<string> RecoveryCodes)
{
    public override string ToString() => $"TotpConfirmation {{ Outcome = {Outcome}, RecoveryCodes = <redacted> }}";
}

public enum TotpManageOutcome
{
    Succeeded,
    InvalidCredentials,
    NotEnabled,

    /// <summary>Disable only: the account has passkeys, which exist only on top of TOTP; remove them first (409).</summary>
    PasskeysExist,
}

public sealed record TotpRecoveryCodesResult(TotpManageOutcome Outcome, IReadOnlyList<string> RecoveryCodes)
{
    public override string ToString() => $"TotpRecoveryCodesResult {{ Outcome = {Outcome}, RecoveryCodes = <redacted> }}";
}

public sealed record TotpStatus(bool Enabled, DateTime? ConfirmedAt, int RecoveryCodesRemaining, bool PendingEnrollment);

public interface ITotpEnrollmentService
{
    Task<TotpStatus> GetStatusAsync(Guid accountId, CancellationToken cancellationToken = default);

    /// <summary>Password-confirmed: generates a new pending secret and returns it once (Base32 + otpauth URI).</summary>
    Task<TotpBeginResult> BeginAsync(Guid accountId, string password, CancellationToken cancellationToken = default);

    /// <summary>A first valid code turns the pending secret into the account's second factor and issues recovery codes (shown once).</summary>
    Task<TotpConfirmation> ConfirmAsync(Guid accountId, string code, CancellationToken cancellationToken = default);

    /// <summary>Password + a valid code (TOTP or recovery) removes the second factor; refused while the account has passkeys.</summary>
    Task<TotpManageOutcome> DisableAsync(Guid accountId, string password, string code, CancellationToken cancellationToken = default);

    /// <summary>Password + a valid code replaces every recovery code; the new set is returned once.</summary>
    Task<TotpRecoveryCodesResult> RegenerateRecoveryCodesAsync(Guid accountId, string password, string code, CancellationToken cancellationToken = default);
}

/// <summary>
/// TOTP enrollment and management for the signed-in account. The account id always comes from the
/// validated session. Every operation that changes the second factor is confirmed with the account
/// password (Argon2, outside any lock) and, once enabled, with a current code; failures collapse to one
/// generic outcome. The TOTP secret is encrypted at rest and leaves the server exactly once, at enrollment.
/// </summary>
public sealed class TotpEnrollmentService : ITotpEnrollmentService
{
    private readonly IAccountRepository _accounts;
    private readonly IAccountPasswordHasher _passwordHasher;
    private readonly ITotpStore _store;
    private readonly ITotpCrypto _crypto;
    private readonly MfaCodeVerifier _codes;
    private readonly TotpOptions _options;
    private readonly TimeProvider _clock;
    private readonly IPasskeyStore? _passkeys;

    public TotpEnrollmentService(
        IAccountRepository accounts,
        IAccountPasswordHasher passwordHasher,
        ITotpStore store,
        ITotpCrypto crypto,
        MfaCodeVerifier codes,
        TotpOptions options,
        TimeProvider clock,
        IPasskeyStore? passkeys = null)
    {
        _accounts = accounts;
        _passwordHasher = passwordHasher;
        _store = store;
        _crypto = crypto;
        _codes = codes;
        _options = options;
        _clock = clock;
        _passkeys = passkeys;
    }

    public async Task<TotpStatus> GetStatusAsync(Guid accountId, CancellationToken cancellationToken = default)
    {
        var enrollment = await _store.GetAsync(accountId, cancellationToken).ConfigureAwait(false);
        if (enrollment is null)
        {
            return new TotpStatus(false, null, 0, false);
        }

        var remaining = enrollment.IsConfirmed ? await _store.CountUnusedRecoveryCodesAsync(accountId, cancellationToken).ConfigureAwait(false) : 0;
        return new TotpStatus(enrollment.IsConfirmed, enrollment.ConfirmedAt, remaining, !enrollment.IsConfirmed);
    }

    public async Task<TotpBeginResult> BeginAsync(Guid accountId, string password, CancellationToken cancellationToken = default)
    {
        var account = await VerifyPasswordAsync(accountId, password, cancellationToken).ConfigureAwait(false);
        if (account is null)
        {
            return new TotpBeginResult(TotpBeginOutcome.InvalidPassword);
        }

        var existing = await _store.GetAsync(accountId, cancellationToken).ConfigureAwait(false);
        if (existing is { IsConfirmed: true })
        {
            return new TotpBeginResult(TotpBeginOutcome.AlreadyEnabled);
        }

        var secret = RandomNumberGenerator.GetBytes(_options.SecretBytes);
        try
        {
            var protectedSecret = _crypto.Protect(secret, accountId);
            var outcome = await _store.StorePendingAsync(accountId, protectedSecret, _clock.GetUtcNow().UtcDateTime, cancellationToken).ConfigureAwait(false);
            if (outcome != TotpPendingOutcome.Stored)
            {
                return new TotpBeginResult(TotpBeginOutcome.AlreadyEnabled);
            }

            var base32 = Base32.Encode(secret);
            var label = account.Email;
            var uri = BuildOtpauthUri(_options.Issuer, label, base32, _options.Digits, _options.PeriodSeconds);
            return new TotpBeginResult(TotpBeginOutcome.Started, base32, uri, _options.Issuer, label);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(secret);
        }
    }

    public async Task<TotpConfirmation> ConfirmAsync(Guid accountId, string code, CancellationToken cancellationToken = default)
    {
        var enrollment = await _store.GetAsync(accountId, cancellationToken).ConfigureAwait(false);
        if (enrollment is null || enrollment.IsConfirmed)
        {
            return new TotpConfirmation(TotpConfirmResult.NotPending, []);
        }

        if (!_codes.TryMatchTotp(enrollment, code, out var step))
        {
            return new TotpConfirmation(TotpConfirmResult.InvalidCode, []);
        }

        var codes = GenerateRecoveryCodes();
        // Bound to the pending secret the code matched: a re-enrollment in between makes this NotPending.
        var outcome = await _store.ConfirmAsync(accountId, enrollment.Secret.Nonce, step, Verifiers(codes), _clock.GetUtcNow().UtcDateTime, cancellationToken).ConfigureAwait(false);
        return outcome == TotpConfirmOutcome.Confirmed
            ? new TotpConfirmation(TotpConfirmResult.Confirmed, codes)
            : new TotpConfirmation(TotpConfirmResult.NotPending, []);
    }

    public async Task<TotpManageOutcome> DisableAsync(Guid accountId, string password, string code, CancellationToken cancellationToken = default)
    {
        // Passkeys are added on top of TOTP and never replace it: refuse before the password and code are checked, so
        // the refusal never uses up a code. The store re-checks under its lock.
        if (_passkeys is not null
            && (await _store.GetAsync(accountId, cancellationToken).ConfigureAwait(false)) is { IsConfirmed: true }
            && await _passkeys.CountAsync(accountId, cancellationToken).ConfigureAwait(false) > 0)
        {
            return TotpManageOutcome.PasskeysExist;
        }

        var outcome = await ConfirmPasswordAndCodeAsync(accountId, password, code, cancellationToken).ConfigureAwait(false);
        if (outcome != TotpManageOutcome.Succeeded)
        {
            return outcome;
        }

        return await _store.DisableAsync(accountId, cancellationToken).ConfigureAwait(false)
            ? TotpManageOutcome.Succeeded
            : TotpManageOutcome.PasskeysExist;
    }

    public async Task<TotpRecoveryCodesResult> RegenerateRecoveryCodesAsync(Guid accountId, string password, string code, CancellationToken cancellationToken = default)
    {
        var outcome = await ConfirmPasswordAndCodeAsync(accountId, password, code, cancellationToken).ConfigureAwait(false);
        if (outcome != TotpManageOutcome.Succeeded)
        {
            return new TotpRecoveryCodesResult(outcome, []);
        }

        var codes = GenerateRecoveryCodes();
        var replaced = await _store.ReplaceRecoveryCodesAsync(accountId, Verifiers(codes), _clock.GetUtcNow().UtcDateTime, cancellationToken).ConfigureAwait(false);
        return replaced ? new TotpRecoveryCodesResult(TotpManageOutcome.Succeeded, codes) : new TotpRecoveryCodesResult(TotpManageOutcome.NotEnabled, []);
    }

    private async Task<TotpManageOutcome> ConfirmPasswordAndCodeAsync(Guid accountId, string password, string code, CancellationToken cancellationToken)
    {
        var enrollment = await _store.GetAsync(accountId, cancellationToken).ConfigureAwait(false);
        if (enrollment is null || !enrollment.IsConfirmed)
        {
            return TotpManageOutcome.NotEnabled;
        }

        // Password first (Argon2, bounded by the admission gate), then the code, so a wrong password never
        // consumes a code or a step.
        var account = await VerifyPasswordAsync(accountId, password, cancellationToken).ConfigureAwait(false);
        if (account is null)
        {
            return TotpManageOutcome.InvalidCredentials;
        }

        return await _codes.VerifyAndConsumeAsync(enrollment, code, cancellationToken).ConfigureAwait(false)
            ? TotpManageOutcome.Succeeded
            : TotpManageOutcome.InvalidCredentials;
    }

    /// <summary>The account when it can sign in and the password matches; otherwise null (no Argon2 for a non-capable account).</summary>
    private async Task<Account?> VerifyPasswordAsync(Guid accountId, string password, CancellationToken cancellationToken)
    {
        if (accountId == Guid.Empty || string.IsNullOrEmpty(password) || password.Length > AccountPasswordPolicy.MaxLength)
        {
            return null;
        }

        var account = await _accounts.GetByIdAsync(accountId, cancellationToken).ConfigureAwait(false);
        if (account is null || account.EmailVerifiedAt is null || account.PasswordHash is null || account.DisabledAt is not null)
        {
            return null;
        }

        var verification = await _passwordHasher.VerifyAsync(password, account.PasswordHash, cancellationToken).ConfigureAwait(false);
        return verification is PasswordVerificationResult.Success or PasswordVerificationResult.NeedsRehash ? account : null;
    }

    private IReadOnlyList<string> GenerateRecoveryCodes()
    {
        var codes = new List<string>(_options.RecoveryCodeCount);
        var seen = new HashSet<string>(StringComparer.Ordinal);
        while (codes.Count < _options.RecoveryCodeCount)
        {
            var code = RecoveryCodes.Generate();
            if (seen.Add(code)) codes.Add(code);
        }

        return codes;
    }

    private IReadOnlyList<byte[]> Verifiers(IReadOnlyList<string> codes)
        => codes.Select(c => _crypto.RecoveryCodeVerifier(RecoveryCodes.Canonicalize(c)!)).ToList();

    /// <summary>otpauth://totp/Issuer:label?secret=…&amp;issuer=Issuer&amp;algorithm=SHA1&amp;digits=6&amp;period=30 (the de-facto Key URI format).</summary>
    public static string BuildOtpauthUri(string issuer, string label, string secretBase32, int digits, int period)
        => $"otpauth://totp/{Uri.EscapeDataString(issuer)}:{Uri.EscapeDataString(label)}?secret={secretBase32}&issuer={Uri.EscapeDataString(issuer)}&algorithm=SHA1&digits={digits}&period={period}";
}
