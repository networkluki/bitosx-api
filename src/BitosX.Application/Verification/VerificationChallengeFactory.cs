using BitosX.Application.Email;

namespace BitosX.Application.Verification;

/// <summary>A challenge row + its encrypted outbox message, plus the raw token (transient).</summary>
public sealed record PreparedChallenge(
    EmailVerificationChallenge Challenge,
    EmailOutboxMessage Outbox,
    string TokenBase64Url,
    DateTime ExpiresAtUtc);

/// <summary>
/// Builds a fresh challenge (verifier only) and its AES-GCM-encrypted outbox message for an
/// account. Centralizes token/payload construction shared by registration, resend and
/// password reset. The outbox message type matches the challenge purpose, and the AEAD AAD
/// binds that type, so a row cannot be re-purposed after the fact.
/// </summary>
public interface IVerificationChallengeFactory
{
    /// <summary>Email-verification challenge (activate account + set first password).</summary>
    PreparedChallenge Create(Guid accountId, string recipientEmail, DateTime nowUtc);

    /// <summary>Password-reset challenge (replace the password of a verified account).</summary>
    PreparedChallenge CreatePasswordReset(Guid accountId, string recipientEmail, DateTime nowUtc);
}

public sealed class VerificationChallengeFactory : IVerificationChallengeFactory
{
    private readonly IEmailVerificationTokenFactory _tokens;
    private readonly IOutboxPayloadProtector _protector;
    private readonly EmailVerificationSecurityOptions _options;

    public VerificationChallengeFactory(
        IEmailVerificationTokenFactory tokens,
        IOutboxPayloadProtector protector,
        EmailVerificationSecurityOptions options)
    {
        _tokens = tokens;
        _protector = protector;
        _options = options;
    }

    public PreparedChallenge Create(Guid accountId, string recipientEmail, DateTime nowUtc)
        => Build(accountId, recipientEmail, nowUtc, ChallengePurposes.EmailVerification, OutboxMessageTypes.EmailVerification);

    public PreparedChallenge CreatePasswordReset(Guid accountId, string recipientEmail, DateTime nowUtc)
        => Build(accountId, recipientEmail, nowUtc, ChallengePurposes.PasswordReset, OutboxMessageTypes.PasswordReset);

    private PreparedChallenge Build(Guid accountId, string recipientEmail, DateTime nowUtc, string purpose, string messageType)
    {
        var token = _tokens.GenerateToken();
        var challengeId = Guid.NewGuid();
        var outboxId = Guid.NewGuid();
        var expiresAt = nowUtc + _options.TokenLifetime;

        var challenge = new EmailVerificationChallenge
        {
            Id = challengeId,
            AccountId = accountId,
            Purpose = purpose,
            TokenHash = token.VerifierHash,
            CreatedAt = nowUtc,
            ExpiresAt = expiresAt,
        };

        var payload = _protector.Protect(
            new OutboxPayload(1, accountId, token.TokenBase64Url, expiresAt, recipientEmail),
            new OutboxAad(outboxId, 1, messageType, recipientEmail));

        var outbox = new EmailOutboxMessage(
            outboxId, challengeId, messageType, recipientEmail, payload, nowUtc, nowUtc);

        return new PreparedChallenge(challenge, outbox, token.TokenBase64Url, expiresAt);
    }
}
