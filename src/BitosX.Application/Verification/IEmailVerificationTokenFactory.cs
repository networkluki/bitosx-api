namespace BitosX.Application.Verification;

/// <summary>A freshly generated verification token and its stored verifier hash.</summary>
/// <param name="TokenBase64Url">The high-entropy token, URL-safe Base64 (for the email link).</param>
/// <param name="VerifierHash">HMAC verifier persisted in the challenge (never the token).</param>
public sealed record GeneratedToken(string TokenBase64Url, byte[] VerifierHash);

/// <summary>
/// Generates 256-bit verification tokens and computes their keyed (peppered)
/// verifier. The plaintext token is never persisted; only the verifier is.
/// </summary>
public interface IEmailVerificationTokenFactory
{
    GeneratedToken GenerateToken();

    /// <summary>Recomputes the verifier for a submitted token (for lookup on verify).</summary>
    byte[] ComputeVerifier(string tokenBase64Url);
}
