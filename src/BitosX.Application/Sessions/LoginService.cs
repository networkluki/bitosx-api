using System.Security.Cryptography;
using BitosX.Application.Abstractions.Persistence;
using BitosX.Application.Accounts;
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

    public LoginService(
        IAccountRepository accounts,
        IAccountPasswordHasher passwordHasher,
        IRefreshTokenFactory refreshTokenFactory,
        ISessionStore sessionStore,
        IAccessTokenService accessTokenService)
    {
        _accounts = accounts;
        _passwordHasher = passwordHasher;
        _refreshTokenFactory = refreshTokenFactory;
        _sessionStore = sessionStore;
        _accessTokenService = accessTokenService;
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
        var verification = _passwordHasher.Verify(command.Password, candidate.PasswordHash);
        if (verification is PasswordVerificationResult.Failed or PasswordVerificationResult.InvalidHashFormat)
        {
            return LoginResult.InvalidCredentials;
        }
        // Success or NeedsRehash → authenticate now; opportunistic rehash is deferred (no hash update here).

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
}
