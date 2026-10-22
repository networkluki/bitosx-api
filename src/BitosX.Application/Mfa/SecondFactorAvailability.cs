namespace BitosX.Application.Mfa;

/// <summary>
/// Whether the server can verify second-factor codes (the Totp capability: <c>Security:TotpKey</c> configured).
/// Registered with Login so the login service can refuse — never bypass — an account whose TOTP is confirmed
/// while the crypto is unavailable.
/// </summary>
public sealed record SecondFactorAvailability(bool Enabled);
