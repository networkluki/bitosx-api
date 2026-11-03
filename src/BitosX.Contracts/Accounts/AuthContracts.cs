namespace BitosX.Contracts.Accounts;

/// <summary>Registration request — email only. No password is accepted here.</summary>
public sealed record RegisterRequest(string Email);

/// <summary>Verify-email request — the token holder chooses the account password here.</summary>
public sealed record VerifyEmailRequest(string Token, string Password);

/// <summary>Request to re-issue a verification email for an unverified account.</summary>
public sealed record ResendVerificationRequest(string Email);

/// <summary>Password-reset request — email only. The response is identical whether or not an account exists.</summary>
public sealed record ForgotPasswordRequest(string Email);

/// <summary>Reset-password request — the emailed token and the new account password. No identity is accepted here.</summary>
public sealed record ResetPasswordRequest(string Token, string Password);

/// <summary>
/// Delete-account request — the current account password as confirmation, plus a TOTP or recovery code
/// (<see cref="Code"/>) when the account has TOTP confirmed. The account to delete is the authenticated
/// caller's own (from the validated JWT), never an id in the body.
/// </summary>
public sealed record DeleteAccountRequest(string Password, string? Code = null);

/// <summary>
/// Change-password request (<c>POST /v1/account/password</c>) — the current account password, the new one
/// (12–128 characters, used exactly as typed), and a TOTP or recovery code (<see cref="Code"/>) when the account
/// has TOTP confirmed. The account is the authenticated caller's own. The vault master password is not affected.
/// </summary>
public sealed record ChangePasswordRequest(string CurrentPassword, string NewPassword, string? Code = null);

/// <summary>Generic response carrying no account state (anti-enumeration).</summary>
public sealed record AcceptedResponse(string Message);

/// <summary>
/// Refresh request — the opaque refresh token only. Account/session identity is resolved from the
/// token by the server, never supplied by the caller. The token is a bearer secret and is never logged.
/// </summary>
public sealed record RefreshRequest(string RefreshToken);

/// <summary>
/// Login request — the account email and password only. Any extra fields are ignored. The
/// optional client descriptor for the session is taken from the <c>User-Agent</c> header, never
/// from the body, so a caller cannot spoof another descriptor field.
/// </summary>
public sealed record LoginRequest(string Email, string Password);

/// <summary>
/// Token pair returned on a successful login or refresh. Carries the short-lived access JWT and the
/// opaque rotating refresh token plus their absolute UTC expiries. Contains no account id, email, or
/// session id. The refresh token is a bearer credential — the client stores it securely and never logs it.
/// </summary>
public sealed record TokenResponse(
    string AccessToken,
    DateTime AccessTokenExpiresAt,
    string RefreshToken,
    DateTime RefreshTokenExpiresAt,
    string TokenType = "Bearer");

/// <summary>
/// The authenticated account's own profile (<c>GET /v1/account/me</c>). Carries only the caller's own
/// account id, display email, verification flag, and creation time. Contains no password hash, phone,
/// disabled/updated state, normalized email, token, or any vault/security-internal field.
/// </summary>
public sealed record MeResponse(Guid AccountId, string Email, bool EmailVerified, DateTime CreatedAt);

/// <summary>
/// A single session in the caller's own session list (<c>GET /v1/account/sessions</c>). <see cref="ExpiresAt"/>
/// is the EFFECTIVE expiry computed by the session-management service — the endpoint never recomputes it.
/// Deliberately excludes the raw user-agent, account id, refresh-token hash/verifier, chain ids, and jti
/// (Decision 8): it is a management view, not session history or a credential.
/// </summary>
public sealed record SessionResponse(Guid Id, DateTime CreatedAt, DateTime LastSeenAt, DateTime ExpiresAt, bool Current);

/// <summary>
/// Answer to <c>POST /v1/auth/login</c> (HTTP 202) when the account has a second factor: the password was
/// accepted, no session exists yet, and the client must present <see cref="MfaToken"/> with a code at
/// <c>POST /v1/auth/login/totp</c> before it expires. The token is an opaque bearer secret for that one step.
/// </summary>
public sealed record MfaChallengeResponse(string MfaToken, DateTime MfaTokenExpiresAt, string Method = "totp");

/// <summary>Second sign-in step: the challenge token from step one and a TOTP code or a recovery code.</summary>
public sealed record TotpLoginRequest(string MfaToken, string Code);

/// <summary>Starts TOTP enrollment for the caller's account; confirmed with the account password.</summary>
public sealed record TotpEnrollRequest(string Password);

/// <summary>
/// The new TOTP secret, returned exactly once at enrollment, as Base32 and as the Key URI authenticator apps
/// read. The client shows it and never stores it.
/// </summary>
public sealed record TotpEnrollResponse(string Secret, string OtpauthUri, string Issuer, string Label, int Digits, int PeriodSeconds);

/// <summary>Confirms a pending enrollment with a first valid code from the authenticator app.</summary>
public sealed record TotpConfirmRequest(string Code);

/// <summary>Single-use recovery codes, returned exactly once (at confirmation or regeneration).</summary>
public sealed record TotpRecoveryCodesResponse(IReadOnlyList<string> RecoveryCodes);

/// <summary>Disables TOTP, or regenerates recovery codes: the account password plus a current TOTP or recovery code.</summary>
public sealed record TotpManageRequest(string Password, string Code);

/// <summary>The caller's second-factor state (<c>GET /v1/account/totp</c>). Carries no secret.</summary>
public sealed record TotpStatusResponse(bool Enabled, DateTime? ConfirmedAt, int RecoveryCodesRemaining, bool PendingEnrollment);
