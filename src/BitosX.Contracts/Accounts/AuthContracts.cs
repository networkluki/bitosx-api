namespace BitosX.Contracts.Accounts;

/// <summary>Registration request — email only. No password is accepted here.</summary>
public sealed record RegisterRequest(string Email);

/// <summary>Verify-email request — the token holder chooses the account password here.</summary>
public sealed record VerifyEmailRequest(string Token, string Password);

/// <summary>Request to re-issue a verification email for an unverified account.</summary>
public sealed record ResendVerificationRequest(string Email);

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
