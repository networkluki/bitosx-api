namespace BitosX.Application.Security;

/// <summary>A freshly generated opaque refresh token and its stored verifier.</summary>
/// <param name="TokenBase64Url">The 256-bit token, unpadded URL-safe Base64 (43 chars). Returned to the caller; never persisted.</param>
/// <param name="Verifier">SHA-256(raw 32 token bytes) — 32 bytes; the only thing persisted (no secret/pepper: the token is already 256 random bits).</param>
public sealed record GeneratedRefreshToken(string TokenBase64Url, byte[] Verifier)
{
    /// <summary>Redacts both the plaintext token and the verifier so neither can leak via ToString.</summary>
    public override string ToString()
        => "GeneratedRefreshToken { TokenBase64Url = <redacted>, Verifier = <redacted> }";
}

/// <summary>
/// Generates 256-bit opaque refresh tokens and computes their <c>SHA-256(raw token bytes)</c>
/// verifier. No server secret is involved — the token is already 256 bits of CSPRNG entropy, so
/// a plain SHA-256 verifier makes offline preimage recovery infeasible while matching the
/// existing 32-byte <c>token_hash</c> storage. The plaintext token is never persisted; only the
/// verifier is. Parsing of a presented token is strict and total (never throws on malformed input).
/// </summary>
public interface IRefreshTokenFactory
{
    /// <summary>Generates a new token (URL-safe Base64) and its verifier.</summary>
    GeneratedRefreshToken Generate();

    /// <summary>
    /// Strictly parses a presented token and computes its verifier. Returns false (no throw)
    /// for any malformed/non-canonical/wrong-length input, before any expensive work.
    /// </summary>
    bool TryComputeVerifier(string presentedTokenBase64Url, out byte[] verifier);
}
