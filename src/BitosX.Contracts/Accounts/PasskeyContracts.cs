using System.Text.Json;

namespace BitosX.Contracts.Accounts;

// Passkeys (WebAuthn). The `options` and `credential` members are the standard WebAuthn JSON serialization
// (PublicKeyCredentialCreationOptionsJSON / PublicKeyCredentialRequestOptionsJSON and the output of
// PublicKeyCredential.toJSON(): base64url strings), exactly as the server's WebAuthn library produces and accepts
// them. No response carries key material or a credential id outside the WebAuthn options themselves.

/// <summary>One passkey of the caller's account (<c>GET /v1/account/passkeys</c>). Never carries key material or the credential id.</summary>
public sealed record PasskeyResponse(Guid Id, string Name, DateTime CreatedAt, DateTime? LastUsedAt, bool BackedUp);

/// <summary>The caller's passkeys and the per-account maximum.</summary>
public sealed record PasskeyListResponse(IReadOnlyList<PasskeyResponse> Passkeys, int Max);

/// <summary>Starts a passkey registration: the account password plus a TOTP or recovery code.</summary>
public sealed record PasskeyRegistrationOptionsRequest(string Password, string Code);

/// <summary>
/// The creation options for <c>navigator.credentials.create</c>, and the opaque id of this registration
/// ceremony (single use, valid for 5 minutes) that the completion must present.
/// </summary>
public sealed record PasskeyRegistrationOptionsResponse(string RegistrationId, JsonElement Options);

/// <summary>Completes a passkey registration: the ceremony id, a name for the passkey (1-64 characters) and the new credential.</summary>
public sealed record PasskeyRegistrationRequest(string RegistrationId, string Name, JsonElement Credential);

/// <summary>The registered passkey (201).</summary>
public sealed record PasskeyCreatedResponse(Guid Id, string Name, DateTime CreatedAt, bool BackedUp);

/// <summary>Renames one of the caller's passkeys.</summary>
public sealed record PasskeyRenameRequest(string Name);

/// <summary>Removes one of the caller's passkeys: the account password plus a TOTP or recovery code.</summary>
public sealed record PasskeyDeleteRequest(string Password, string Code);

/// <summary>Second sign-in step with a passkey: asks for request options for the challenge token from step one.</summary>
public sealed record PasskeyMfaOptionsRequest(string MfaToken);

/// <summary>The request options for <c>navigator.credentials.get</c> in the second sign-in step.</summary>
public sealed record PasskeyMfaOptionsResponse(JsonElement Options);

/// <summary>Second sign-in step with a passkey: the challenge token and the assertion.</summary>
public sealed record PasskeyMfaLoginRequest(string MfaToken, JsonElement Credential);

/// <summary>
/// Sign-in without email and password: request options for a discoverable credential, and the opaque id of this
/// ceremony (single use, valid for 5 minutes) that the completion must present.
/// </summary>
public sealed record PasskeyLoginOptionsResponse(string AssertionId, JsonElement Options);

/// <summary>Sign-in without email and password: the ceremony id and the assertion.</summary>
public sealed record PasskeyLoginRequest(string AssertionId, JsonElement Credential);
