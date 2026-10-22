using BitosX.Application.Abstractions.Persistence;
using BitosX.Application.Security;
using BitosX.Application.Verification;

namespace BitosX.Application.Accounts;

public sealed record ForgotPasswordCommand(string Email);

public sealed record ResetPasswordCommand(string Token, string Password);

public enum ForgotPasswordResult
{
    /// <summary>The only outcome: identical for unknown, unverified, disabled and eligible accounts.</summary>
    Accepted,
}

public enum ResetPasswordResult
{
    Reset,
    Invalid,
    InvalidPassword,
}

public interface IPasswordResetService
{
    Task<ForgotPasswordResult> RequestAsync(ForgotPasswordCommand command, CancellationToken cancellationToken = default);
    Task<ResetPasswordResult> ResetAsync(ResetPasswordCommand command, CancellationToken cancellationToken = default);
}

/// <summary>
/// Account-password reset by emailed link. <see cref="RequestAsync"/> issues a reset challenge only for
/// a verified, enabled account with a password and always reports <see cref="ForgotPasswordResult.Accepted"/>
/// (anti-enumeration; the email is the only side channel). <see cref="ResetAsync"/> mirrors email
/// verification: policy check and verifier pre-check before any Argon2 work, hashing outside any DB
/// lock, then an authoritative transaction that replaces the hash, consumes the token and revokes every
/// session. This never touches the vault: the master password and the envelope are unaffected.
/// </summary>
public sealed class PasswordResetService : IPasswordResetService
{
    private readonly IAccountRepository _accounts;
    private readonly IPasswordResetStore _store;
    private readonly IEmailVerificationTokenFactory _tokens;
    private readonly IVerificationChallengeFactory _challengeFactory;
    private readonly IAccountPasswordHasher _passwordHasher;
    private readonly EmailVerificationSecurityOptions _options;
    private readonly TimeProvider _clock;

    public PasswordResetService(
        IAccountRepository accounts,
        IPasswordResetStore store,
        IEmailVerificationTokenFactory tokens,
        IVerificationChallengeFactory challengeFactory,
        IAccountPasswordHasher passwordHasher,
        EmailVerificationSecurityOptions options,
        TimeProvider clock)
    {
        _accounts = accounts;
        _store = store;
        _tokens = tokens;
        _challengeFactory = challengeFactory;
        _passwordHasher = passwordHasher;
        _options = options;
        _clock = clock;
    }

    public async Task<ForgotPasswordResult> RequestAsync(ForgotPasswordCommand command, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(command);

        if (!EmailAddressValidator.IsValid(command.Email))
        {
            return ForgotPasswordResult.Accepted; // malformed input: nothing to do, same generic outcome
        }

        var normalized = EmailNormalizer.Normalize(command.Email);
        var account = await _accounts.GetByNormalizedEmailAsync(normalized, cancellationToken).ConfigureAwait(false);

        // Only an account that can sign in can have its password reset. An unverified account has no
        // password yet (verification sets it); a disabled account gets nothing.
        if (account is null
            || account.EmailVerifiedAt is null
            || account.PasswordHash is null
            || account.DisabledAt is not null)
        {
            return ForgotPasswordResult.Accepted;
        }

        var now = _clock.GetUtcNow().UtcDateTime;
        // The email goes to the address on the account, never to the address the caller typed.
        var prepared = _challengeFactory.CreatePasswordReset(account.Id, account.Email, now);

        // Issued / SkippedTooSoon / SkippedDeliveryInProgress / AccountNotEligible all map to Accepted.
        await _store.IssueChallengeAsync(
            account.Id, prepared.Challenge, prepared.Outbox, now, _options.MinResendInterval, cancellationToken).ConfigureAwait(false);

        return ForgotPasswordResult.Accepted;
    }

    public async Task<ResetPasswordResult> ResetAsync(ResetPasswordCommand command, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(command);

        // Cheap checks first: policy, then token shape. No Argon2 for a bad request.
        if (AccountPasswordPolicy.Validate(command.Password) != PasswordPolicyResult.Valid)
        {
            return ResetPasswordResult.InvalidPassword;
        }

        if (string.IsNullOrEmpty(command.Token))
        {
            return ResetPasswordResult.Invalid;
        }

        byte[] verifier;
        try
        {
            verifier = _tokens.ComputeVerifier(command.Token);
        }
        catch (FormatException)
        {
            return ResetPasswordResult.Invalid;
        }

        // Phase A: non-locking pre-check gates the expensive hash (no CPU amplification for bogus tokens).
        var now = _clock.GetUtcNow().UtcDateTime;
        var active = await _store.FindActiveChallengeByVerifierAsync(verifier, now, cancellationToken).ConfigureAwait(false);
        if (active is null)
        {
            return ResetPasswordResult.Invalid;
        }

        // Phase B: Argon2 with no DB lock held.
        var phc = await _passwordHasher.HashAsync(command.Password, cancellationToken).ConfigureAwait(false);

        // Phase C: authoritative locked transaction (store owns the clock; re-checks everything).
        var outcome = await _store.FinalizeResetAsync(verifier, phc, cancellationToken).ConfigureAwait(false);
        return outcome == PasswordResetOutcome.Reset ? ResetPasswordResult.Reset : ResetPasswordResult.Invalid;
    }
}
