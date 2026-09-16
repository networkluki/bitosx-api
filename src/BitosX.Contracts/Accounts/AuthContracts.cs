namespace BitosX.Contracts.Accounts;

/// <summary>Registration request — email only. No password is accepted here.</summary>
public sealed record RegisterRequest(string Email);

/// <summary>Verify-email request — the token holder chooses the account password here.</summary>
public sealed record VerifyEmailRequest(string Token, string Password);

/// <summary>Request to re-issue a verification email for an unverified account.</summary>
public sealed record ResendVerificationRequest(string Email);

/// <summary>Generic response carrying no account state (anti-enumeration).</summary>
public sealed record AcceptedResponse(string Message);
