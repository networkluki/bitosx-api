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
/// - <see cref="EmailHeldInOutbox"/>: Development/Testing only — mail is queued but never delivered
///   (the local live stack reads it from the outbox). Never available in Production.
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

    /// <summary>
    /// Second factor (TOTP): requires <see cref="LoginEnabled"/> plus <c>Security:TotpKey</c>, the key that encrypts
    /// stored TOTP secrets and keys recovery-code verifiers. Without it, enrollment and the second sign-in step are
    /// unavailable (503); an account that already has TOTP confirmed cannot sign in at all (fail closed, never a bypass).
    /// </summary>
    public bool TotpEnabled { get; init; }

    /// <summary>
    /// <c>Email:HoldInOutbox</c> (Development/Testing only, refused in any other environment): verification and
    /// reset mail is queued in the outbox exactly as with delivery, but no SMTP sender or dispatcher exists, so it
    /// stays there (encrypted) for the local live stack's outbox reader. Mutually exclusive with
    /// <see cref="EmailDeliveryEnabled"/>; requires <see cref="EmailVerificationEnabled"/>.
    /// </summary>
    public bool EmailHeldInOutbox { get; init; }

    /// <summary>Register, resend and forgot-password may queue mail: it is delivered, or (Development/Testing) held.</summary>
    public bool EmailQueueingEnabled => EmailDeliveryEnabled || EmailHeldInOutbox;

    public static AccountCapabilities None { get; } = new()
    {
        AccountCoreEnabled = false,
        EmailVerificationEnabled = false,
        EmailDeliveryEnabled = false,
        LoginEnabled = false,
    };
}
