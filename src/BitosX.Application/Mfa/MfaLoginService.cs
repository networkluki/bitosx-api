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
/// active challenge, asks the per-account attempt limiter, and RESERVES one attempt atomically before the
/// code is looked at (so concurrent requests can never check more than <see cref="TotpOptions.MaxMfaAttempts"/>
/// codes per challenge). It then re-reads the account and checks the password hash is still the one that was
/// verified, matches the code without consuming it, claims the challenge (single use), and only then uses up
/// the code and creates the session exactly as a password-only login does — so a code is never spent by a
/// request that lost the challenge. A wrong code keeps its reserved attempt; once the attempts are used up the
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
    private readonly IMfaAttemptLimiter _limiter;
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
        IMfaAttemptLimiter limiter,
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
        _limiter = limiter;
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

        // Per-account budget across all of the account's challenges (each challenge also has its own limit).
        var admission = _limiter.TryAdmit(challenge.AccountId);
        if (admission.Admission == MfaAttemptAdmission.RateLimited)
        {
            return LoginResult.RateLimited(admission.RetryAfter);
        }

        if (admission.Admission != MfaAttemptAdmission.Admitted)
        {
            return LoginResult.TemporarilyUnavailable;
        }

        // Reserve the attempt BEFORE the code is checked: the reservation is the only thing that admits a check.
        if (!await _challenges.TryReserveAttemptAsync(challenge.Id, _options.MaxMfaAttempts, now, cancellationToken).ConfigureAwait(false))
        {
            return LoginResult.InvalidCredentials; // spent, expired, or out of attempts
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

        var match = await _codes.TryMatchAsync(enrollment, command.Code, cancellationToken).ConfigureAwait(false);
        if (match is null)
        {
            await _challenges.CloseIfAttemptsExhaustedAsync(challenge.Id, _options.MaxMfaAttempts, now, cancellationToken).ConfigureAwait(false);
            return LoginResult.InvalidCredentials;
        }

        // Single use: a concurrent completion with the same token loses here, before it spends any code.
        if (!await _challenges.TryConsumeAsync(challenge.Id, now, cancellationToken).ConfigureAwait(false))
        {
            return LoginResult.InvalidCredentials;
        }

        // The store is the authority on replay: a code used meanwhile (another sign-in, TOTP management) loses here.
        if (!await _codes.ConsumeAsync(enrollment, match, cancellationToken).ConfigureAwait(false))
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
