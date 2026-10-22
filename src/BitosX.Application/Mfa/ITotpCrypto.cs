namespace BitosX.Application.Mfa;

/// <summary>A TOTP secret encrypted at rest (AES-256-GCM under the server's TotpKey, AAD = account id + version).</summary>
public sealed record ProtectedTotpSecret(byte Version, byte[] Nonce, byte[] Ciphertext, byte[] Tag);

/// <summary>
/// Server-side cryptography for the second factor: encrypts TOTP secrets at rest and computes the
/// keyed verifier for recovery codes. Both use keys derived from <c>Security:TotpKey</c>; neither
/// touches vault material. Available only when the Totp capability is enabled.
/// </summary>
public interface ITotpCrypto
{
    ProtectedTotpSecret Protect(ReadOnlySpan<byte> secret, Guid accountId);

    /// <summary>Returns false (no throw) when the ciphertext does not authenticate for this account.</summary>
    bool TryUnprotect(ProtectedTotpSecret protectedSecret, Guid accountId, out byte[] secret);

    /// <summary>HMAC-SHA256 verifier of a canonical recovery code (32 bytes). Keyed, so a leaked table cannot be brute-forced offline.</summary>
    byte[] RecoveryCodeVerifier(string canonicalCode);
}
