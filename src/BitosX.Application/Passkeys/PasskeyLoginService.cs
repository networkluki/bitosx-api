using System.Security.Cryptography;
using BitosX.Application.Abstractions.Persistence;
using BitosX.Application.Accounts;
using BitosX.Application.Mfa;
using BitosX.Application.Security;
using BitosX.Application.Sessions;

namespace BitosX.Application.Passkeys;

/// <summary>Second sign-in step with a passkey: the challenge token from the password step and the assertion.</summary>
public sealed record PasskeyMfaLoginCommand(string? MfaToken, string CredentialJson)
{
    public override string ToString() => "PasskeyMfaLoginCommand { MfaToken = <redacted>, CredentialJson = <redacted> }";
}

/// <summary>Sign-in without email and password: the ceremony id and the assertion; the user agent describes the new session.</summary>
public sealed record PasskeyLoginCommand(string? AssertionId, string CredentialJson, string? UserAgent)
{
    public override string ToString() => $"PasskeyLoginCommand {{ AssertionId = <redacted>, CredentialJson = <redacted>, UserAgent = {UserAgent} }}";
}

/// <summary>Request options for the browser, plus (passwordless only) the opaque ceremony id. Null options = refused.</summary>
public sealed record PasskeyAssertionOptions(string OptionsJson, string? AssertionId)
{
    public override string ToString() => "PasskeyAssertionOptions { AssertionId = <redacted> }";
}

public interface IPasskeyLoginService
{
    /// <summary>Request options for the second sign-in step (allowCredentials = the account's passkeys, UV preferred), or null (401).</summary>
    Task<PasskeyAssertionOptions?> BeginSecondFactorAsync(string? mfaToken, CancellationToken cancellationToken = default);

    /// <summary>Completes the second sign-in step with a passkey. Every failure is InvalidCredentials and uses up one MFA attempt.</summary>
    Task<LoginResult> CompleteSecondFactorAsync(PasskeyMfaLoginCommand command, CancellationToken cancellationToken = default);

    /// <summary>Request options for a discoverable credential (empty allowCredentials, UV required) and the ceremony id.</summary>
    Task<PasskeyAssertionOptions> BeginPasswordlessAsync(CancellationToken cancellationToken = default);

    /// <summary>Sign-in with a passkey alone (it counts as both factors). Every failure is InvalidCredentials.</summary>
    Task<LoginResult> CompletePasswordlessAsync(PasskeyLoginCommand command, CancellationToken cancellationToken = default);
}

/// <summary>
/// Sign-in with a passkey, as the second factor after the password or on its own.
///
/// Second factor: mirrors <see cref="MfaLoginService"/> exactly — the opaque challenge token names the account, the
/// per-account limiter is asked, and one attempt is RESERVED atomically before anything is verified, so a failed
/// passkey costs an attempt like a wrong code and the challenge dies when they are used up. The passkey ceremony of
/// the challenge is claimed (single use) before the assertion is verified; the credential must belong to the
/// challenge's account; then the MFA challenge is claimed, and only then is the use recorded (compare-and-set on the
/// signature counter) and the session created.
///
/// Passwordless: the ceremony id names an anonymous challenge; the assertion must carry a user handle that equals
/// the stored credential's and the account's, user verification must be reported (UV flag), and the account must be
/// verified, enabled and still have TOTP confirmed (passkeys only exist on top of it). A counter that does not
/// increase is refused as a clone signal (logged). Every failure is one generic outcome.
/// </summary>
public sealed class PasskeyLoginService : IPasskeyLoginService
{
    private readonly IAccountRepository _accounts;
    private readonly IMfaChallengeStore _mfaChallenges;
    private readonly ITotpStore _totp;
    private readonly IPasskeyStore _passkeys;
    private readonly IWebAuthnChallengeStore _ceremonies;
    private readonly IWebAuthnRelyingParty _relyingParty;
    private readonly IRefreshTokenFactory _tokens;
    private readonly ISessionStore _sessions;
    private readonly IAccessTokenService _accessTokens;
    private readonly IMfaAttemptLimiter _limiter;
    private readonly TotpOptions _options;
    private readonly IPasskeySecurityLog _log;
    private readonly TimeProvider _clock;

    public PasskeyLoginService(
        IAccountRepository accounts,
        IMfaChallengeStore mfaChallenges,
        ITotpStore totp,
        IPasskeyStore passkeys,
        IWebAuthnChallengeStore ceremonies,
        IWebAuthnRelyingParty relyingParty,
        IRefreshTokenFactory tokens,
        ISessionStore sessions,
        IAccessTokenService accessTokens,
        IMfaAttemptLimiter limiter,
        TotpOptions options,
        IPasskeySecurityLog log,
        TimeProvider clock)
    {
        _accounts = accounts;
        _mfaChallenges = mfaChallenges;
        _totp = totp;
        _passkeys = passkeys;
        _ceremonies = ceremonies;
        _relyingParty = relyingParty;
        _tokens = tokens;
        _sessions = sessions;
        _accessTokens = accessTokens;
        _limiter = limiter;
        _options = options;
        _log = log;
        _clock = clock;
    }

    public async Task<PasskeyAssertionOptions?> BeginSecondFactorAsync(string? mfaToken, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(mfaToken) || !_tokens.TryComputeVerifier(mfaToken, out var verifier))
        {
            return null;
        }

        var now = _clock.GetUtcNow().UtcDateTime;
        var challenge = await _mfaChallenges.FindActiveAsync(verifier, now, cancellationToken).ConfigureAwait(false);
        if (challenge is null)
        {
            return null;
        }

        var passkeys = await _passkeys.ListAsync(challenge.AccountId, cancellationToken).ConfigureAwait(false);
        if (passkeys.Count == 0)
        {
            return null; // nothing to sign with: same answer as a dead token
        }

        var options = _relyingParty.BeginAssertion(PasskeyManagementService.Descriptors(passkeys), requireUserVerification: false);
        // Never longer than the MFA challenge it belongs to.
        var expiresAt = Min(now + WebAuthnOptions.ChallengeLifetime, challenge.ExpiresAt);
        await _ceremonies.UpsertForMfaAsync(new WebAuthnChallenge(
            Guid.NewGuid(), WebAuthnChallengePurpose.Mfa, null, challenge.AccountId, challenge.Id, options.Challenge, now, expiresAt),
            cancellationToken).ConfigureAwait(false);
        return new PasskeyAssertionOptions(options.OptionsJson, null);
    }

    public async Task<LoginResult> CompleteSecondFactorAsync(PasskeyMfaLoginCommand command, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(command);
        if (string.IsNullOrEmpty(command.MfaToken) || string.IsNullOrEmpty(command.CredentialJson) || !_tokens.TryComputeVerifier(command.MfaToken, out var verifier))
        {
            return LoginResult.InvalidCredentials;
        }

        var now = _clock.GetUtcNow().UtcDateTime;
        var challenge = await _mfaChallenges.FindActiveAsync(verifier, now, cancellationToken).ConfigureAwait(false);
        if (challenge is null)
        {
            return LoginResult.InvalidCredentials;
        }

        // Same per-account budget and the same per-challenge reservation as a TOTP or recovery code.
        var admission = _limiter.TryAdmit(challenge.AccountId);
        if (admission.Admission == MfaAttemptAdmission.RateLimited)
        {
            return LoginResult.RateLimited(admission.RetryAfter);
        }

        if (admission.Admission != MfaAttemptAdmission.Admitted)
        {
            return LoginResult.TemporarilyUnavailable;
        }

        if (!await _mfaChallenges.TryReserveAttemptAsync(challenge.Id, _options.MaxMfaAttempts, now, cancellationToken).ConfigureAwait(false))
        {
            return LoginResult.InvalidCredentials;
        }

        var account = await _accounts.GetByIdAsync(challenge.AccountId, cancellationToken).ConfigureAwait(false);
        if (account is null
            || account.EmailVerifiedAt is null
            || account.PasswordHash is null
            || account.DisabledAt is not null
            || !CryptographicOperations.FixedTimeEquals(LoginService.PasswordHashFingerprint(account.PasswordHash), challenge.PasswordHashFingerprint))
        {
            await _mfaChallenges.TryConsumeAsync(challenge.Id, now, cancellationToken).ConfigureAwait(false);
            return LoginResult.InvalidCredentials;
        }

        var enrollment = await _totp.GetAsync(account.Id, cancellationToken).ConfigureAwait(false);
        if (enrollment is not { IsConfirmed: true })
        {
            await _mfaChallenges.TryConsumeAsync(challenge.Id, now, cancellationToken).ConfigureAwait(false);
            return LoginResult.InvalidCredentials;
        }

        var check = await VerifySecondFactorAsync(challenge.Id, account.Id, command.CredentialJson, now, cancellationToken).ConfigureAwait(false);
        if (check.Reason is not null)
        {
            _log.Refused("mfa", check.Reason, account.Id, check.Passkey?.Id);
            await _mfaChallenges.CloseIfAttemptsExhaustedAsync(challenge.Id, _options.MaxMfaAttempts, now, cancellationToken).ConfigureAwait(false);
            return LoginResult.InvalidCredentials;
        }

        // Single use of the MFA challenge: a concurrent completion (code or passkey) loses here.
        if (!await _mfaChallenges.TryConsumeAsync(challenge.Id, now, cancellationToken).ConfigureAwait(false))
        {
            return LoginResult.InvalidCredentials;
        }

        var passkey = check.Passkey!;
        if (!await _passkeys.TryRecordUseAsync(passkey.Id, passkey.SignCount, check.Verification!.SignCount, check.Verification.BackedUp, now, cancellationToken).ConfigureAwait(false))
        {
            _log.Refused("mfa", "counter-race", account.Id, passkey.Id);
            return LoginResult.InvalidCredentials;
        }

        var result = await CreateSessionAsync(account, challenge.UserAgent, cancellationToken).ConfigureAwait(false);
        if (result.Outcome == LoginOutcome.Succeeded)
        {
            _log.Used(account.Id, passkey.Id, passwordless: false);
        }

        return result;
    }

    private async Task<(string? Reason, StoredPasskey? Passkey, AssertionVerification? Verification)> VerifySecondFactorAsync(
        Guid mfaChallengeId, Guid accountId, string credentialJson, DateTime now, CancellationToken cancellationToken)
    {
        var ceremony = await _ceremonies.FindActiveForMfaAsync(mfaChallengeId, now, cancellationToken).ConfigureAwait(false);
        if (ceremony is null || ceremony.AccountId != accountId)
        {
            return ("no-ceremony", null, null);
        }

        if (!await _ceremonies.TryClaimAsync(ceremony.Id, now, cancellationToken).ConfigureAwait(false))
        {
            return ("ceremony-spent", null, null);
        }

        var claim = _relyingParty.ReadAssertion(credentialJson);
        if (claim is null)
        {
            return ("malformed", null, null);
        }

        var passkeys = await _passkeys.ListAsync(accountId, cancellationToken).ConfigureAwait(false);
        var passkey = passkeys.FirstOrDefault(p => CryptographicOperations.FixedTimeEquals(p.CredentialId, claim.CredentialId));
        if (passkey is null)
        {
            return ("unknown-credential", null, null); // unknown, or another account's credential
        }

        var verification = await _relyingParty.VerifyAssertionAsync(
            ceremony.Challenge, PasskeyManagementService.Descriptors(passkeys), requireUserVerification: false, credentialJson,
            passkey.PublicKey, checked((uint)passkey.SignCount), passkey.CredentialId, passkey.UserHandle, cancellationToken).ConfigureAwait(false);
        return verification.Outcome switch
        {
            WebAuthnVerification.Verified => (null, passkey, verification),
            WebAuthnVerification.CounterRegression => ("counter-regression", passkey, null),
            _ => (verification.Reason ?? "verification-failed", passkey, null),
        };
    }

    public async Task<PasskeyAssertionOptions> BeginPasswordlessAsync(CancellationToken cancellationToken = default)
    {
        var options = _relyingParty.BeginAssertion([], requireUserVerification: true);
        var handle = _tokens.Generate();
        try
        {
            var now = _clock.GetUtcNow().UtcDateTime;
            await _ceremonies.CreateAsync(new WebAuthnChallenge(
                Guid.NewGuid(), WebAuthnChallengePurpose.Passwordless, handle.Verifier, null, null, options.Challenge,
                now, now + WebAuthnOptions.ChallengeLifetime), cancellationToken).ConfigureAwait(false);
            return new PasskeyAssertionOptions(options.OptionsJson, handle.TokenBase64Url);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(handle.Verifier);
        }
    }

    public async Task<LoginResult> CompletePasswordlessAsync(PasskeyLoginCommand command, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(command);
        if (string.IsNullOrEmpty(command.AssertionId) || string.IsNullOrEmpty(command.CredentialJson) || !_tokens.TryComputeVerifier(command.AssertionId, out var verifier))
        {
            return LoginResult.InvalidCredentials;
        }

        var now = _clock.GetUtcNow().UtcDateTime;
        var ceremony = await _ceremonies.FindActiveByHandleAsync(verifier, WebAuthnChallengePurpose.Passwordless, now, cancellationToken).ConfigureAwait(false);
        if (ceremony is null || !await _ceremonies.TryClaimAsync(ceremony.Id, now, cancellationToken).ConfigureAwait(false))
        {
            return LoginResult.InvalidCredentials;
        }

        var claim = _relyingParty.ReadAssertion(command.CredentialJson);
        if (claim is null)
        {
            return Refuse("malformed", null, null);
        }

        // A discoverable credential always returns its user handle; without one there is nothing to bind the account to.
        if (claim.UserHandle is not { Length: > 0 } presentedHandle)
        {
            return Refuse("no-user-handle", null, null);
        }

        var passkey = await _passkeys.FindByCredentialIdAsync(claim.CredentialId, cancellationToken).ConfigureAwait(false);
        if (passkey is null)
        {
            return Refuse("unknown-credential", null, null);
        }

        var accountHandle = await _passkeys.GetUserHandleAsync(passkey.AccountId, cancellationToken).ConfigureAwait(false);
        if (!CryptographicOperations.FixedTimeEquals(presentedHandle, passkey.UserHandle)
            || accountHandle is null
            || !CryptographicOperations.FixedTimeEquals(accountHandle, passkey.UserHandle))
        {
            return Refuse("user-handle-mismatch", passkey.AccountId, passkey.Id);
        }

        var account = await _accounts.GetByIdAsync(passkey.AccountId, cancellationToken).ConfigureAwait(false);
        if (account is null || account.EmailVerifiedAt is null || account.PasswordHash is null || account.DisabledAt is not null)
        {
            return Refuse("account-state", passkey.AccountId, passkey.Id);
        }

        var enrollment = await _totp.GetAsync(account.Id, cancellationToken).ConfigureAwait(false);
        if (enrollment is not { IsConfirmed: true })
        {
            return Refuse("no-totp", account.Id, passkey.Id);
        }

        var verification = await _relyingParty.VerifyAssertionAsync(
            ceremony.Challenge, [], requireUserVerification: true, command.CredentialJson,
            passkey.PublicKey, checked((uint)passkey.SignCount), passkey.CredentialId, passkey.UserHandle, cancellationToken).ConfigureAwait(false);
        if (verification.Outcome == WebAuthnVerification.CounterRegression)
        {
            return Refuse("counter-regression", account.Id, passkey.Id);
        }

        if (verification.Outcome != WebAuthnVerification.Verified)
        {
            return Refuse(verification.Reason ?? "verification-failed", account.Id, passkey.Id);
        }

        // The library already enforces UV for this ceremony; a passkey alone stands in for both factors, so check again.
        if (!verification.UserVerified)
        {
            return Refuse("uv-missing", account.Id, passkey.Id);
        }

        if (!await _passkeys.TryRecordUseAsync(passkey.Id, passkey.SignCount, verification.SignCount, verification.BackedUp, now, cancellationToken).ConfigureAwait(false))
        {
            return Refuse("counter-race", account.Id, passkey.Id);
        }

        var result = await CreateSessionAsync(account, command.UserAgent, cancellationToken).ConfigureAwait(false);
        if (result.Outcome == LoginOutcome.Succeeded)
        {
            _log.Used(account.Id, passkey.Id, passwordless: true);
        }

        return result;
    }

    private LoginResult Refuse(string reason, Guid? accountId, Guid? passkeyId)
    {
        _log.Refused("passwordless", reason, accountId, passkeyId);
        return LoginResult.InvalidCredentials;
    }

    /// <summary>The session exactly as a password login creates it (the store re-checks the account state under its lock).</summary>
    private async Task<LoginResult> CreateSessionAsync(Account account, string? userAgent, CancellationToken cancellationToken)
    {
        var generated = _tokens.Generate();
        try
        {
            var created = await _sessions.CreateOnLoginAsync(new LoginSessionCreateRequest
            {
                AccountId = account.Id,
                NormalizedEmail = account.NormalizedEmail,
                ExpectedPasswordHash = account.PasswordHash!,
                InitialRefreshVerifier = generated.Verifier,
                UserAgent = userAgent,
            }, cancellationToken).ConfigureAwait(false);

            if (created.Outcome != LoginSessionCreateOutcome.Created)
            {
                return LoginResult.InvalidCredentials;
            }

            var access = _accessTokens.Issue(created.AccountId, created.SessionId, created.SessionCreatedAt);
            return LoginResult.Succeeded(access.Token, access.ExpiresAt, generated.TokenBase64Url, created.RefreshTokenExpiresAt);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(generated.Verifier);
        }
    }

    private static DateTime Min(DateTime a, DateTime b) => a < b ? a : b;
}
