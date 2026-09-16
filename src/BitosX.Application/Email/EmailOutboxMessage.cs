namespace BitosX.Application.Email;

/// <summary>A verification email queued for out-of-band delivery (encrypted payload).</summary>
public sealed record EmailOutboxMessage(
    Guid Id,
    Guid ChallengeId,
    string MessageType,
    string RecipientEmail,
    ProtectedOutboxPayload Payload,
    DateTime CreatedAt,
    DateTime AvailableAt);

/// <summary>Message-type constants for the outbox.</summary>
public static class OutboxMessageTypes
{
    public const string EmailVerification = "email_verification";
}
