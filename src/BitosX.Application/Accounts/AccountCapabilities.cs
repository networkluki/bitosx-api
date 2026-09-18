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
/// - <see cref="LoginEnabled"/>: login / session / access-JWT / refresh. An INDEPENDENT capability
///   layered on AccountCore — it requires <see cref="AccountCoreEnabled"/> plus valid JWT/login
///   configuration (current signing key + mandatory kid, etc.), but does NOT require
///   EmailVerification, EmailDelivery, SMTP, or any refresh-token secret (the refresh verifier is
///   SHA-256 of the raw token, with no server pepper).
/// </summary>
public sealed class AccountCapabilities
{
    public required bool AccountCoreEnabled { get; init; }
    public required bool EmailVerificationEnabled { get; init; }
    public required bool EmailDeliveryEnabled { get; init; }
    public required bool LoginEnabled { get; init; }

    public static AccountCapabilities None { get; } = new()
    {
        AccountCoreEnabled = false,
        EmailVerificationEnabled = false,
        EmailDeliveryEnabled = false,
        LoginEnabled = false,
    };
}
