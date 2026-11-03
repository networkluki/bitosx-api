namespace BitosX.Application.Passkeys;

/// <summary>A credential named in options (exclude/allow list): the credential id and its stored transports hint.</summary>
public sealed record PasskeyDescriptor(byte[] CredentialId, string? Transports);

/// <summary>Options for the browser, as the standard WebAuthn JSON, and the challenge they carry (to be stored server-side).</summary>
public sealed record WebAuthnCeremonyOptions(byte[] Challenge, string OptionsJson)
{
    public override string ToString() => "WebAuthnCeremonyOptions { Challenge = <redacted> }";
}

/// <summary>A verified new credential, ready to be stored.</summary>
public sealed record VerifiedRegistration(
    byte[] CredentialId, byte[] PublicKey, uint SignCount, Guid AaGuid, bool BackupEligible, bool BackedUp, string? Transports);

/// <summary>What an assertion claims before it is verified: the credential id and the user handle (if the authenticator returned one).</summary>
public sealed record PasskeyAssertionClaim(byte[] CredentialId, byte[]? UserHandle);

public enum WebAuthnVerification
{
    Verified,

    /// <summary>Any verification failure (origin, RP ID hash, challenge, flags, signature, malformed input …).</summary>
    Failed,

    /// <summary>A valid signature with a counter that did not increase: a possible cloned authenticator.</summary>
    CounterRegression,
}

/// <summary>The outcome of a registration verification; <see cref="Reason"/> is for the security log only, never the client.</summary>
public sealed record RegistrationVerification(WebAuthnVerification Outcome, VerifiedRegistration? Credential, string? Reason);

/// <summary>The outcome of an assertion verification; <see cref="Reason"/> is for the security log only, never the client.</summary>
public sealed record AssertionVerification(WebAuthnVerification Outcome, uint SignCount, bool BackedUp, bool UserVerified, string? Reason);

/// <summary>
/// The WebAuthn relying party: builds options and verifies responses (origin, RP ID hash, challenge, type, flags,
/// algorithm, signature, counter) for the configured <see cref="WebAuthnOptions"/>. Never throws for malformed client
/// input: it is reported as <see cref="WebAuthnVerification.Failed"/>. Stateless — the caller stores the challenge
/// and passes it back in.
/// </summary>
public interface IWebAuthnRelyingParty
{
    /// <summary>
    /// Creation options: resident key and user verification required, attestation <c>none</c>, ES256/EdDSA/RS256,
    /// <c>user.id</c> = <paramref name="userHandle"/>, <c>user.name</c> = <c>displayName</c> = <paramref name="userName"/>.
    /// </summary>
    WebAuthnCeremonyOptions BeginRegistration(byte[] userHandle, string userName, IReadOnlyList<PasskeyDescriptor> excludeCredentials);

    /// <summary>Verifies an attestation response (<paramref name="credentialJson"/>, the browser's JSON) against the stored challenge.</summary>
    Task<RegistrationVerification> VerifyRegistrationAsync(
        byte[] challenge, byte[] userHandle, string userName, string credentialJson, CancellationToken cancellationToken = default);

    /// <summary>Request options with <paramref name="allowCredentials"/> (empty for a discoverable credential) and UV required or preferred.</summary>
    WebAuthnCeremonyOptions BeginAssertion(IReadOnlyList<PasskeyDescriptor> allowCredentials, bool requireUserVerification);

    /// <summary>Reads the credential id and user handle from an assertion response without verifying anything. Null when malformed.</summary>
    PasskeyAssertionClaim? ReadAssertion(string credentialJson);

    /// <summary>
    /// Verifies an assertion against the stored challenge, the options it was issued with, and the stored credential.
    /// A returned user handle must equal <paramref name="expectedUserHandle"/>.
    /// </summary>
    Task<AssertionVerification> VerifyAssertionAsync(
        byte[] challenge,
        IReadOnlyList<PasskeyDescriptor> allowCredentials,
        bool requireUserVerification,
        string credentialJson,
        byte[] storedPublicKey,
        uint storedSignCount,
        byte[] expectedCredentialId,
        byte[] expectedUserHandle,
        CancellationToken cancellationToken = default);
}

/// <summary>Security log lines for passkeys (no secrets, no credential ids, no email addresses).</summary>
public interface IPasskeySecurityLog
{
    void Registered(Guid accountId, Guid passkeyId, bool backupEligible);

    void Renamed(Guid accountId, Guid passkeyId);

    void Deleted(Guid accountId, Guid passkeyId);

    /// <summary>A successful sign-in; <paramref name="passwordless"/> false = second factor after the password.</summary>
    void Used(Guid accountId, Guid passkeyId, bool passwordless);

    /// <summary>A refused registration or sign-in. <paramref name="reason"/> is a fixed code (never client text).</summary>
    void Refused(string ceremony, string reason, Guid? accountId, Guid? passkeyId);
}

/// <summary>Writes nothing (hosts and tests without a logger).</summary>
public sealed class NullPasskeySecurityLog : IPasskeySecurityLog
{
    public static NullPasskeySecurityLog Instance { get; } = new();

    public void Registered(Guid accountId, Guid passkeyId, bool backupEligible) { }

    public void Renamed(Guid accountId, Guid passkeyId) { }

    public void Deleted(Guid accountId, Guid passkeyId) { }

    public void Used(Guid accountId, Guid passkeyId, bool passwordless) { }

    public void Refused(string ceremony, string reason, Guid? accountId, Guid? passkeyId) { }
}
