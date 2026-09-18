using BitosX.Application.Abstractions.Persistence;
using BitosX.Application.Accounts;
using BitosX.Application.Security;

namespace BitosX.Application.Verification;

public sealed record VerifyEmailCommand(string Token, string Password);
public sealed record ResendCommand(string Email);

public enum VerifyResult
{
    Verified,
    Invalid,
    InvalidPassword,
}

public enum ResendResult
{
    Accepted,
}

public interface IEmailVerificationService
{
    Task<VerifyResult> VerifyAsync(VerifyEmailCommand command, CancellationToken cancellationToken = default);
    Task<ResendResult> ResendAsync(ResendCommand command, CancellationToken cancellationToken = default);
}

/// <summary>
/// Verifies email ownership and finalizes the account password (two-phase:
/// non-locking pre-check → hash → authoritative transaction), and re-issues
/// verification (resend). Argon2 never runs for an invalid/expired/consumed
/// token; no DB lock is held during hashing.
/// </summary>
public sealed class EmailVerificationService : IEmailVerificationService
{
    private readonly IAccountRepository _accounts;
    private readonly IEmailVerificationStore _store;
    private readonly IEmailVerificationTokenFactory _tokens;
    private readonly IVerificationChallengeFactory _challengeFactory;
    private readonly IAccountPasswordHasher _hasher;
    private readonly EmailVerificationSecurityOptions _options;
    private readonly TimeProvider _clock;

    public EmailVerificationService(
        IAccountRepository accounts,
        IEmailVerificationStore store,
        IEmailVerificationTokenFactory tokens,
        IVerificationChallengeFactory challengeFactory,
        IAccountPasswordHasher hasher,
        EmailVerificationSecurityOptions options,
        TimeProvider clock)
    {
        _accounts = accounts;
        _store = store;
        _tokens = tokens;
        _challengeFactory = challengeFactory;
        _hasher = hasher;
        _options = options;
        _clock = clock;
    }

    public async Task<VerifyResult> VerifyAsync(VerifyEmailCommand command, CancellationToken cancellationToken = default)
    {
        // Phase A — cheap gate (no hashing on invalid input).
        if (AccountPasswordPolicy.Validate(command.Password) != PasswordPolicyResult.Valid)
        {
            return VerifyResult.InvalidPassword;
        }

        byte[] verifier;
        try
        {
            verifier = _tokens.ComputeVerifier(command.Token);
        }
        catch (FormatException)
        {
            return VerifyResult.Invalid; // malformed token — never hashed
        }

        var precheckNow = _clock.GetUtcNow().UtcDateTime;
        var active = await _store.FindActiveChallengeByVerifierAsync(verifier, precheckNow, cancellationToken).ConfigureAwait(false);
        if (active is null)
        {
            return VerifyResult.Invalid; // bogus/expired/consumed/invalidated — no Argon2
        }

        // Phase B — expensive hash, no DB lock held.
        var phc = await _hasher.HashAsync(command.Password, cancellationToken).ConfigureAwait(false);

        // Phase C — authoritative transaction. The store acquires the row lock and reads
        // its own authoritative timestamp AFTER the lock is held (so a token that expired
        // during Argon2 OR during a lock wait is rejected against the 30-min TTL). The
        // pre-check time above is not treated as authoritative.
        var outcome = await _store.FinalizeVerificationAsync(verifier, phc, cancellationToken).ConfigureAwait(false);
        return outcome == VerificationOutcome.Verified ? VerifyResult.Verified : VerifyResult.Invalid;
    }

    public async Task<ResendResult> ResendAsync(ResendCommand command, CancellationToken cancellationToken = default)
    {
        // Always generic Accepted; reveal nothing about account state.
        if (!EmailAddressValidator.IsValid(command.Email))
        {
            return ResendResult.Accepted;
        }

        var normalized = EmailNormalizer.Normalize(command.Email);
        var account = await _accounts.GetByNormalizedEmailAsync(normalized, cancellationToken).ConfigureAwait(false);

        // Only active, unverified accounts are re-issued a challenge (disabled accounts never).
        if (account is not null && account.EmailVerifiedAt is null && account.DisabledAt is null)
        {
            var now = _clock.GetUtcNow().UtcDateTime;
            var prepared = _challengeFactory.Create(account.Id, account.Email, now);
            await _store.ReplaceActiveChallengeAsync(
                account.Id, prepared.Challenge, prepared.Outbox, now, _options.MinResendInterval, cancellationToken)
                .ConfigureAwait(false);
        }

        return ResendResult.Accepted;
    }
}
