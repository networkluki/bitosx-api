namespace BitosX.Application.Accounts;

/// <summary>
/// Authoritative, composition-time view of which account capabilities are enabled.
/// Determined once at startup and consulted via DI (never re-derived from config
/// in endpoints). Higher capabilities imply the lower ones.
///
/// - <see cref="AccountCoreEnabled"/>: DB + password hashing + (future) login/session/JWT.
///   Independent of SMTP.
/// - <see cref="EmailVerificationEnabled"/>: register/verify/resend + outbox persistence
///   (requires the verification pepper + outbox key). Verifying an already-issued token
///   does NOT require SMTP delivery.
/// - <see cref="EmailDeliveryEnabled"/>: physical delivery of queued mail (requires SMTP
///   credentials). Optional; its absence must not disable AccountCore or verification.
/// </summary>
public sealed class AccountCapabilities
{
    public required bool AccountCoreEnabled { get; init; }
    public required bool EmailVerificationEnabled { get; init; }
    public required bool EmailDeliveryEnabled { get; init; }

    public static AccountCapabilities None { get; } = new()
    {
        AccountCoreEnabled = false,
        EmailVerificationEnabled = false,
        EmailDeliveryEnabled = false,
    };
}
