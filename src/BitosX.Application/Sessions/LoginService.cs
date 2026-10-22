using System.Security.Cryptography;
using System.Text;
using BitosX.Application.Abstractions.Persistence;
using BitosX.Application.Accounts;
using BitosX.Application.Mfa;
using BitosX.Application.Security;

namespace BitosX.Application.Sessions;

/// <summary>
/// Login orchestration. Bounds + normalizes input, reads the (non-locking) candidate, decides
/// login-capability WITHOUT running Argon2 for non-capable accounts, verifies the password with
/// Argon2 OUTSIDE any DB lock, generates the initial refresh token, creates the session atomically
/// (the store re-checks the exact PHC under the account lock), and only THEN — after the store has
/// committed — issues the access JWT using the store's authoritative timestamp. Every credential
/// failure collapses to <see cref="LoginOutcome.InvalidCredentials"/>; unexpected faults propagate.
/// Never runs a dummy Argon2, never rehashes, never sends the plaintext password or refresh token to
/// the store.
/// </summary>
public sealed class LoginService : ILoginService
{
    private readonly IAccountRepository _accounts;
    private readonly IAccountPasswordHasher _passwordHasher;
    private readonly IRefreshTokenFactory _refreshTokenFactory;
    private readonly ISessionStore _sessionStore;
    private readonly IAccessTokenService _accessTokenService;
    private readonly ITotpStore _totp;
    private readonly IMfaChallengeStore _mfaChallenges;
    private readonly TotpOptions _totpOptions;
    private readonly SecondFactorAvailability _secondFactor;
    private readonly TimeProvider _clock;

    public LoginService(
        IAccountRepository accounts,
        IAccountPasswordHasher passwordHasher,
        IRefreshTokenFactory refreshTokenFactory,
        ISessionStore sessionStore,
        IAccessTokenService accessTokenService,
        ITotpStore totp,
        IMfaChallengeStore mfaChallenges,
        TotpOptions totpOptions,
        SecondFactorAvailability secondFactor,
        TimeProvider clock)
    {
        _accounts = accounts;
        _passwordHasher = passwordHasher;
        _refreshTokenFactory = refreshTokenFactory;
        _sessionStore = sessionStore;
        _accessTokenService = accessTokenService;
        _totp = totp;
        _mfaChallenges = mfaChallenges;
        _totpOptions = totpOptions;
        _secondFactor = secondFactor;
        _clock = clock;
    }

    public async Task<LoginResult> LoginAsync(LoginCommand command, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(command);

        // Bounds before any expensive work (no Trim/normalize of the password).
        if (string.IsNullOrEmpty(command.Password) || command.Password.Length > AccountPasswordPolicy.MaxLength)
        {
            return LoginResult.InvalidCredentials;
        }

        // Validates non-null/non-empty, ≤ 320, and structural format — all before repo/Argon2.
        if (!EmailAddressValidator.IsValid(command.Email))
        {
            return LoginResult.InvalidCredentials;
        }

        var normalizedEmail = EmailNormalizer.Normalize(command.Email);
        var candidate = await _accounts.GetByNormalizedEmailAsync(normalizedEmail, cancellationToken).ConfigureAwait(false);

        // Login-capability gate — NO Argon2 for a non-capable/unknown account (approved DoS decision).
        if (candidate is null
            || candidate.EmailVerifiedAt is null
            || candidate.PasswordHash is null
            || candidate.DisabledAt is not null)
        {
            return LoginResult.InvalidCredentials;
        }

        // Argon2 verification OUTSIDE any transaction/row lock.
        var verification = await _passwordHasher.VerifyAsync(command.Password, candidate.PasswordHash, cancellationToken).ConfigureAwait(false);
        if (verification is PasswordVerificationResult.Failed or PasswordVerificationResult.InvalidHashFormat)
        {
            return LoginResult.InvalidCredentials;
        }
        // Success or NeedsRehash → authenticate now; opportunistic rehash is deferred (no hash update here).

        // Second factor: a confirmed TOTP enrollment turns the password into step one. No session, no
        // JWT, no refresh token is issued here — only an opaque, short-lived challenge token whose verifier
        // is stored together with a fingerprint of the hash that was just verified.
        var enrollment = await _totp.GetAsync(candidate.Id, cancellationToken).ConfigureAwait(false);
        if (enrollment is { IsConfirmed: true })
        {
            if (!_secondFactor.Enabled)
            {
                return LoginResult.MfaUnavailable; // the server cannot verify codes: refuse, never bypass
            }

            var mfa = _refreshTokenFactory.Generate(); // same 256-bit opaque token + SHA-256 verifier scheme
            try
            {
                var now = _clock.GetUtcNow().UtcDateTime;
                var expiresAt = now + _totpOptions.MfaChallengeLifetime;
                await _mfaChallenges.CreateAsync(new MfaChallenge(
                    Guid.NewGuid(), candidate.Id, mfa.Verifier, PasswordHashFingerprint(candidate.PasswordHash),
                    command.UserAgent, now, expiresAt), cancellationToken).ConfigureAwait(false);
                return LoginResult.MfaRequired(mfa.TokenBase64Url, expiresAt);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(mfa.Verifier);
            }
        }

        var generated = _refreshTokenFactory.Generate();
        try
        {
            var storeResult = await _sessionStore.CreateOnLoginAsync(new LoginSessionCreateRequest
            {
                AccountId = candidate.Id,
                NormalizedEmail = normalizedEmail,
                ExpectedPasswordHash = candidate.PasswordHash, // the EXACT PHC Argon2 verified
                InitialRefreshVerifier = generated.Verifier,   // SHA-256 verifier only, never the plaintext token
                UserAgent = command.UserAgent,
            }, cancellationToken).ConfigureAwait(false);

            if (storeResult.Outcome != LoginSessionCreateOutcome.Created)
            {
                return LoginResult.InvalidCredentials; // no JWT minted on InvalidAccountState
            }

            // Only after the session is committed: issue the access JWT using the store's authoritative time.
            var access = _accessTokenService.Issue(storeResult.AccountId, storeResult.SessionId, storeResult.SessionCreatedAt);

            return LoginResult.Succeeded(access.Token, access.ExpiresAt, generated.TokenBase64Url, storeResult.RefreshTokenExpiresAt);
        }
        finally
        {
            // Best-effort clear the verifier the service owns (the store took its own snapshot). The
            // Base64URL token is an immutable managed string and cannot be reliably zeroed.
            CryptographicOperations.ZeroMemory(generated.Verifier);
        }
    }

    /// <summary>SHA-256 of the PHC string: lets the second step detect a password change without storing the hash twice.</summary>
    public static byte[] PasswordHashFingerprint(string passwordHashPhc) => SHA256.HashData(Encoding.UTF8.GetBytes(passwordHashPhc));
}
