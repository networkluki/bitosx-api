using System.Security.Cryptography;
using BitosX.Application.Abstractions.Persistence;
using BitosX.Application.Accounts;
using BitosX.Application.Security;
using BitosX.Application.Sessions;

namespace BitosX.Application.Mfa;

/// <summary>The second sign-in step: the opaque token from step one plus a TOTP or recovery code.</summary>
public sealed record MfaLoginCommand(string MfaToken, string Code)
{
    public override string ToString() => "MfaLoginCommand { MfaToken = <redacted>, Code = <redacted> }";
}

public interface IMfaLoginService
{
    /// <summary>Succeeded with tokens, or InvalidCredentials for every failure (unknown/expired/spent token, wrong code, changed password).</summary>
    Task<LoginResult> CompleteAsync(MfaLoginCommand command, CancellationToken cancellationToken = default);
}

/// <summary>
/// Completes a login whose password step issued an MFA challenge. Strictly parses the token, finds the
/// active challenge, re-reads the account and checks the password hash is still the one that was verified,
/// verifies and consumes the code, consumes the challenge (single use), and only then creates the session
/// exactly as a password-only login does. A wrong code counts against the challenge; at the limit the
/// challenge dies and the password must be entered again. No Argon2 runs here.
/// </summary>
public sealed class MfaLoginService : IMfaLoginService
{
    private readonly IAccountRepository _accounts;
    private readonly IMfaChallengeStore _challenges;
    private readonly ITotpStore _totp;
    private readonly MfaCodeVerifier _codes;
    private readonly IRefreshTokenFactory _tokens;
    private readonly ISessionStore _sessions;
    private readonly IAccessTokenService _accessTokens;
    private readonly TotpOptions _options;
    private readonly TimeProvider _clock;

    public MfaLoginService(
        IAccountRepository accounts,
        IMfaChallengeStore challenges,
        ITotpStore totp,
        MfaCodeVerifier codes,
        IRefreshTokenFactory tokens,
        ISessionStore sessions,
        IAccessTokenService accessTokens,
        TotpOptions options,
        TimeProvider clock)
    {
        _accounts = accounts;
        _challenges = challenges;
        _totp = totp;
        _codes = codes;
        _tokens = tokens;
        _sessions = sessions;
        _accessTokens = accessTokens;
        _options = options;
        _clock = clock;
    }

    public async Task<LoginResult> CompleteAsync(MfaLoginCommand command, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(command);

        if (string.IsNullOrEmpty(command.Code) || command.Code.Length > 32 || !_tokens.TryComputeVerifier(command.MfaToken, out var verifier))
        {
            return LoginResult.InvalidCredentials;
        }

        var now = _clock.GetUtcNow().UtcDateTime;
        var challenge = await _challenges.FindActiveAsync(verifier, now, cancellationToken).ConfigureAwait(false);
        if (challenge is null)
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
            // The password changed (or the account died) between the steps: the challenge is worthless.
            await _challenges.TryConsumeAsync(challenge.Id, now, cancellationToken).ConfigureAwait(false);
            return LoginResult.InvalidCredentials;
        }

        var enrollment = await _totp.GetAsync(account.Id, cancellationToken).ConfigureAwait(false);
        if (enrollment is null || !enrollment.IsConfirmed)
        {
            await _challenges.TryConsumeAsync(challenge.Id, now, cancellationToken).ConfigureAwait(false);
            return LoginResult.InvalidCredentials; // TOTP was disabled meanwhile: start over with the password
        }

        if (!await _codes.VerifyAndConsumeAsync(enrollment, command.Code, cancellationToken).ConfigureAwait(false))
        {
            await _challenges.RecordFailedAttemptAsync(challenge.Id, _options.MaxMfaAttempts, now, cancellationToken).ConfigureAwait(false);
            return LoginResult.InvalidCredentials;
        }

        // Single use: a concurrent completion with the same token loses here.
        if (!await _challenges.TryConsumeAsync(challenge.Id, now, cancellationToken).ConfigureAwait(false))
        {
            return LoginResult.InvalidCredentials;
        }

        var generated = _tokens.Generate();
        try
        {
            var created = await _sessions.CreateOnLoginAsync(new LoginSessionCreateRequest
            {
                AccountId = account.Id,
                NormalizedEmail = account.NormalizedEmail,
                ExpectedPasswordHash = account.PasswordHash,
                InitialRefreshVerifier = generated.Verifier,
                UserAgent = challenge.UserAgent,
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
}
