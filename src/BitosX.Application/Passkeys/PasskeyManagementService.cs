using System.Security.Cryptography;
using BitosX.Application.Abstractions.Persistence;
using BitosX.Application.Accounts;
using BitosX.Application.Mfa;
using BitosX.Application.Security;

namespace BitosX.Application.Passkeys;

public enum PasskeyRegistrationBeginOutcome
{
    Started,

    /// <summary>Wrong password or code, or an account that cannot do this: one generic 403.</summary>
    InvalidCredentials,

    /// <summary>The account has no confirmed TOTP: passkeys are added on top of it (409).</summary>
    TwoFactorRequired,

    /// <summary>The account already has <see cref="WebAuthnOptions.MaxPasskeysPerAccount"/> passkeys (409).</summary>
    LimitReached,
}

public sealed record PasskeyRegistrationBegin(PasskeyRegistrationBeginOutcome Outcome, string? RegistrationId = null, string? OptionsJson = null)
{
    public override string ToString() => $"PasskeyRegistrationBegin {{ Outcome = {Outcome}, RegistrationId = <redacted> }}";
}

public enum PasskeyRegistrationOutcome
{
    Created,

    /// <summary>The name is empty, too long or contains control characters (400; the ceremony is not used up).</summary>
    InvalidName,

    /// <summary>No live registration with this id for this account: expired, already used, or never issued (410).</summary>
    Expired,

    /// <summary>The credential did not verify, or it is already registered (400, generic).</summary>
    Invalid,

    LimitReached,

    TwoFactorRequired,
}

public sealed record PasskeyRegistration(PasskeyRegistrationOutcome Outcome, StoredPasskey? Passkey = null);

public enum PasskeyChangeOutcome
{
    Succeeded,

    /// <summary>The account has no passkey with this id (also another account's passkey): 404.</summary>
    NotFound,

    InvalidName,

    /// <summary>Wrong password or code: one generic 403.</summary>
    InvalidCredentials,
}

public interface IPasskeyManagementService
{
    Task<IReadOnlyList<StoredPasskey>> ListAsync(Guid accountId, CancellationToken cancellationToken = default);

    /// <summary>Password + a TOTP or recovery code: creation options for a new passkey and the registration id.</summary>
    Task<PasskeyRegistrationBegin> BeginRegistrationAsync(Guid accountId, string? password, string? code, CancellationToken cancellationToken = default);

    /// <summary>Verifies the new credential against the registration's challenge and stores it under <paramref name="name"/>.</summary>
    Task<PasskeyRegistration> CompleteRegistrationAsync(Guid accountId, string? registrationId, string? name, string credentialJson, CancellationToken cancellationToken = default);

    Task<PasskeyChangeOutcome> RenameAsync(Guid accountId, Guid passkeyId, string? name, CancellationToken cancellationToken = default);

    /// <summary>Password + a TOTP or recovery code removes the passkey.</summary>
    Task<PasskeyChangeOutcome> DeleteAsync(Guid accountId, Guid passkeyId, string? password, string? code, CancellationToken cancellationToken = default);
}

/// <summary>
/// Passkey management for the signed-in account (the account id always comes from the validated session).
/// Registration and removal are confirmed like TOTP management: the account password (Argon2, outside any lock)
/// and then a TOTP or recovery code, which is used up; failures collapse to one generic outcome. A passkey can only
/// be added while TOTP is confirmed, and the store re-checks that (and the per-account maximum) atomically when it
/// inserts. The ceremony is server-side: a random challenge bound to the account and to an opaque registration id
/// (only its SHA-256 is stored), single use, valid for <see cref="WebAuthnOptions.ChallengeLifetime"/>.
/// </summary>
public sealed class PasskeyManagementService : IPasskeyManagementService
{
    private readonly IAccountRepository _accounts;
    private readonly IAccountPasswordHasher _passwordHasher;
    private readonly ITotpStore _totp;
    private readonly MfaCodeVerifier _codes;
    private readonly IPasskeyStore _passkeys;
    private readonly IWebAuthnChallengeStore _challenges;
    private readonly IWebAuthnRelyingParty _relyingParty;
    private readonly IRefreshTokenFactory _handles;
    private readonly IPasskeySecurityLog _log;
    private readonly TimeProvider _clock;

    public PasskeyManagementService(
        IAccountRepository accounts,
        IAccountPasswordHasher passwordHasher,
        ITotpStore totp,
        MfaCodeVerifier codes,
        IPasskeyStore passkeys,
        IWebAuthnChallengeStore challenges,
        IWebAuthnRelyingParty relyingParty,
        IRefreshTokenFactory handles,
        IPasskeySecurityLog log,
        TimeProvider clock)
    {
        _accounts = accounts;
        _passwordHasher = passwordHasher;
        _totp = totp;
        _codes = codes;
        _passkeys = passkeys;
        _challenges = challenges;
        _relyingParty = relyingParty;
        _handles = handles;
        _log = log;
        _clock = clock;
    }

    public Task<IReadOnlyList<StoredPasskey>> ListAsync(Guid accountId, CancellationToken cancellationToken = default)
        => _passkeys.ListAsync(accountId, cancellationToken);

    public async Task<PasskeyRegistrationBegin> BeginRegistrationAsync(Guid accountId, string? password, string? code, CancellationToken cancellationToken = default)
    {
        // State checks first, so neither a doomed request nor a wrong password ever uses up a code.
        var enrollment = await _totp.GetAsync(accountId, cancellationToken).ConfigureAwait(false);
        if (enrollment is not { IsConfirmed: true })
        {
            return new PasskeyRegistrationBegin(PasskeyRegistrationBeginOutcome.TwoFactorRequired);
        }

        var existing = await _passkeys.ListAsync(accountId, cancellationToken).ConfigureAwait(false);
        if (existing.Count >= WebAuthnOptions.MaxPasskeysPerAccount)
        {
            return new PasskeyRegistrationBegin(PasskeyRegistrationBeginOutcome.LimitReached);
        }

        var account = await VerifyPasswordAndCodeAsync(accountId, enrollment, password, code, cancellationToken).ConfigureAwait(false);
        if (account is null)
        {
            return new PasskeyRegistrationBegin(PasskeyRegistrationBeginOutcome.InvalidCredentials);
        }

        var userHandle = await _passkeys.GetOrAssignUserHandleAsync(
            accountId, RandomNumberGenerator.GetBytes(WebAuthnOptions.UserHandleBytes), cancellationToken).ConfigureAwait(false);
        if (userHandle is null)
        {
            return new PasskeyRegistrationBegin(PasskeyRegistrationBeginOutcome.InvalidCredentials);
        }

        var options = _relyingParty.BeginRegistration(userHandle, account.Email, Descriptors(existing));
        var handle = _handles.Generate();
        try
        {
            var now = _clock.GetUtcNow().UtcDateTime;
            await _challenges.CreateAsync(new WebAuthnChallenge(
                Guid.NewGuid(), WebAuthnChallengePurpose.Register, handle.Verifier, accountId, null, options.Challenge,
                now, now + WebAuthnOptions.ChallengeLifetime), cancellationToken).ConfigureAwait(false);
            return new PasskeyRegistrationBegin(PasskeyRegistrationBeginOutcome.Started, handle.TokenBase64Url, options.OptionsJson);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(handle.Verifier);
        }
    }

    public async Task<PasskeyRegistration> CompleteRegistrationAsync(
        Guid accountId, string? registrationId, string? name, string credentialJson, CancellationToken cancellationToken = default)
    {
        // A bad name is the user's typo: refuse it before the single-use ceremony is spent.
        var normalizedName = WebAuthnOptions.NormalizeName(name);
        if (normalizedName is null)
        {
            return new PasskeyRegistration(PasskeyRegistrationOutcome.InvalidName);
        }

        if (string.IsNullOrEmpty(registrationId) || !_handles.TryComputeVerifier(registrationId, out var verifier))
        {
            return new PasskeyRegistration(PasskeyRegistrationOutcome.Expired);
        }

        var now = _clock.GetUtcNow().UtcDateTime;
        var ceremony = await _challenges.FindActiveByHandleAsync(verifier, WebAuthnChallengePurpose.Register, now, cancellationToken).ConfigureAwait(false);
        if (ceremony is null || ceremony.AccountId != accountId)
        {
            return new PasskeyRegistration(PasskeyRegistrationOutcome.Expired); // another account's id is as unknown as none
        }

        // Single use: the ceremony is spent now, whatever the verification below says.
        if (!await _challenges.TryClaimAsync(ceremony.Id, now, cancellationToken).ConfigureAwait(false))
        {
            return new PasskeyRegistration(PasskeyRegistrationOutcome.Expired);
        }

        var account = await _accounts.GetByIdAsync(accountId, cancellationToken).ConfigureAwait(false);
        var userHandle = await _passkeys.GetUserHandleAsync(accountId, cancellationToken).ConfigureAwait(false);
        if (account is null || account.DisabledAt is not null || userHandle is null)
        {
            _log.Refused("register", "account-state", accountId, null);
            return new PasskeyRegistration(PasskeyRegistrationOutcome.Invalid);
        }

        var verification = await _relyingParty.VerifyRegistrationAsync(ceremony.Challenge, userHandle, account.Email, credentialJson, cancellationToken).ConfigureAwait(false);
        if (verification.Outcome != WebAuthnVerification.Verified || verification.Credential is not { } credential)
        {
            _log.Refused("register", verification.Reason ?? "verification-failed", accountId, null);
            return new PasskeyRegistration(PasskeyRegistrationOutcome.Invalid);
        }

        // WebAuthn §7.1 step 26: a credential id registered before (here or to anyone else) is refused, not moved.
        if (await _passkeys.CredentialIdExistsAsync(credential.CredentialId, cancellationToken).ConfigureAwait(false))
        {
            _log.Refused("register", "duplicate-credential", accountId, null);
            return new PasskeyRegistration(PasskeyRegistrationOutcome.Invalid);
        }

        // Stored to the microsecond (DATETIME(6)): answer exactly what every later read returns.
        var createdAt = new DateTime(now.Ticks - (now.Ticks % TimeSpan.TicksPerMicrosecond), DateTimeKind.Utc);
        var passkey = new StoredPasskey(
            Guid.NewGuid(), accountId, credential.CredentialId, credential.PublicKey, credential.SignCount, userHandle, normalizedName,
            credential.AaGuid, credential.BackupEligible, credential.BackedUp, credential.Transports, createdAt, null);
        var outcome = await _passkeys.InsertAsync(passkey, WebAuthnOptions.MaxPasskeysPerAccount, cancellationToken).ConfigureAwait(false);
        switch (outcome)
        {
            case PasskeyInsertOutcome.Inserted:
                _log.Registered(accountId, passkey.Id, passkey.BackupEligible);
                return new PasskeyRegistration(PasskeyRegistrationOutcome.Created, passkey);
            case PasskeyInsertOutcome.LimitReached:
                _log.Refused("register", "limit-reached", accountId, null);
                return new PasskeyRegistration(PasskeyRegistrationOutcome.LimitReached);
            case PasskeyInsertOutcome.TwoFactorRequired:
                _log.Refused("register", "no-totp", accountId, null);
                return new PasskeyRegistration(PasskeyRegistrationOutcome.TwoFactorRequired);
            default:
                _log.Refused("register", "duplicate-credential", accountId, null);
                return new PasskeyRegistration(PasskeyRegistrationOutcome.Invalid);
        }
    }

    public async Task<PasskeyChangeOutcome> RenameAsync(Guid accountId, Guid passkeyId, string? name, CancellationToken cancellationToken = default)
    {
        var normalizedName = WebAuthnOptions.NormalizeName(name);
        if (normalizedName is null)
        {
            return PasskeyChangeOutcome.InvalidName;
        }

        if (!await _passkeys.RenameAsync(accountId, passkeyId, normalizedName, cancellationToken).ConfigureAwait(false))
        {
            return PasskeyChangeOutcome.NotFound;
        }

        _log.Renamed(accountId, passkeyId);
        return PasskeyChangeOutcome.Succeeded;
    }

    public async Task<PasskeyChangeOutcome> DeleteAsync(Guid accountId, Guid passkeyId, string? password, string? code, CancellationToken cancellationToken = default)
    {
        var existing = await _passkeys.ListAsync(accountId, cancellationToken).ConfigureAwait(false);
        if (!existing.Any(p => p.Id == passkeyId))
        {
            return PasskeyChangeOutcome.NotFound; // before the password: an unknown id never uses up a code
        }

        // Passkeys exist only on top of a confirmed TOTP; without it (removed out of band) nothing can confirm this.
        var enrollment = await _totp.GetAsync(accountId, cancellationToken).ConfigureAwait(false);
        if (await VerifyPasswordAndCodeAsync(accountId, enrollment, password, code, cancellationToken).ConfigureAwait(false) is null)
        {
            return PasskeyChangeOutcome.InvalidCredentials;
        }

        if (!await _passkeys.DeleteAsync(accountId, passkeyId, cancellationToken).ConfigureAwait(false))
        {
            return PasskeyChangeOutcome.NotFound;
        }

        _log.Deleted(accountId, passkeyId);
        return PasskeyChangeOutcome.Succeeded;
    }

    /// <summary>Password first (Argon2, bounded by the admission gate), then the code, so a wrong password never consumes a code.</summary>
    private async Task<Account?> VerifyPasswordAndCodeAsync(
        Guid accountId, TotpEnrollment? enrollment, string? password, string? code, CancellationToken cancellationToken)
    {
        if (enrollment is not { IsConfirmed: true }
            || accountId == Guid.Empty
            || string.IsNullOrEmpty(password)
            || password.Length > AccountPasswordPolicy.MaxLength)
        {
            return null;
        }

        var account = await _accounts.GetByIdAsync(accountId, cancellationToken).ConfigureAwait(false);
        if (account is null || account.EmailVerifiedAt is null || account.PasswordHash is null || account.DisabledAt is not null)
        {
            return null;
        }

        var verification = await _passwordHasher.VerifyAsync(password, account.PasswordHash, cancellationToken).ConfigureAwait(false);
        if (verification is not (PasswordVerificationResult.Success or PasswordVerificationResult.NeedsRehash))
        {
            return null;
        }

        return await _codes.VerifyAndConsumeAsync(enrollment, code, cancellationToken).ConfigureAwait(false) ? account : null;
    }

    internal static IReadOnlyList<PasskeyDescriptor> Descriptors(IEnumerable<StoredPasskey> passkeys)
        => passkeys.Select(p => new PasskeyDescriptor(p.CredentialId, p.Transports)).ToList();
}
