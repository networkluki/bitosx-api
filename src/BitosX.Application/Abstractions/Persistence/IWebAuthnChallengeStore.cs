namespace BitosX.Application.Abstractions.Persistence;

/// <summary>What a WebAuthn challenge was issued for; a challenge is only ever accepted for its own purpose.</summary>
public enum WebAuthnChallengePurpose
{
    /// <summary>Passkey registration by a signed-in account (bound to the account and to a registration id).</summary>
    Register = 1,

    /// <summary>The second sign-in step (bound to the account through its MFA challenge).</summary>
    Mfa = 2,

    /// <summary>Sign-in without email and password (bound to an assertion id; the account is unknown until the assertion names it).</summary>
    Passwordless = 3,
}

/// <summary>
/// A server-side WebAuthn ceremony. <see cref="Challenge"/> is the random challenge sent to the client in the options;
/// it is kept as is because the WebAuthn library verifies the response against the original challenge bytes. It is
/// not a secret (the client sees it), and it is single use: a ceremony is claimed exactly once, whatever the outcome.
/// <see cref="HandleVerifier"/> is the SHA-256 of the opaque registration/assertion id the client holds (never the id).
/// </summary>
public sealed record WebAuthnChallenge(
    Guid Id,
    WebAuthnChallengePurpose Purpose,
    byte[]? HandleVerifier,
    Guid? AccountId,
    Guid? MfaChallengeId,
    byte[] Challenge,
    DateTime CreatedAt,
    DateTime ExpiresAt)
{
    public override string ToString() => $"WebAuthnChallenge {{ Id = {Id}, Purpose = {Purpose}, Challenge = <redacted> }}";
}

public interface IWebAuthnChallengeStore
{
    /// <summary>Stores a registration or passwordless ceremony (it carries a handle verifier).</summary>
    Task CreateAsync(WebAuthnChallenge challenge, CancellationToken cancellationToken = default);

    /// <summary>
    /// Stores the passkey ceremony of a second sign-in step, replacing an earlier one of the same MFA challenge (one
    /// live passkey ceremony per MFA challenge; asking for options again invalidates the previous challenge).
    /// </summary>
    Task UpsertForMfaAsync(WebAuthnChallenge challenge, CancellationToken cancellationToken = default);

    /// <summary>An unclaimed, unexpired ceremony by handle verifier and purpose, or null.</summary>
    Task<WebAuthnChallenge?> FindActiveByHandleAsync(byte[] handleVerifier, WebAuthnChallengePurpose purpose, DateTime nowUtc, CancellationToken cancellationToken = default);

    /// <summary>The unclaimed, unexpired passkey ceremony of an MFA challenge, or null.</summary>
    Task<WebAuthnChallenge?> FindActiveForMfaAsync(Guid mfaChallengeId, DateTime nowUtc, CancellationToken cancellationToken = default);

    /// <summary>Claims the ceremony iff it is still unclaimed and unexpired (single use, one conditional UPDATE). False means it was spent, replaced or expired meanwhile.</summary>
    Task<bool> TryClaimAsync(Guid challengeId, DateTime nowUtc, CancellationToken cancellationToken = default);
}
