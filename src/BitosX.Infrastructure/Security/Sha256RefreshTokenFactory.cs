using System.Security.Cryptography;
using BitosX.Application.Security;

namespace BitosX.Infrastructure.Security;

/// <summary>
/// Generates 256-bit opaque refresh tokens (URL-safe unpadded Base64) and computes their verifier
/// as <c>SHA-256(raw 32 token bytes)</c>. No server secret is involved — the token is already 256
/// bits of CSPRNG entropy, so a plain SHA-256 verifier makes offline preimage recovery infeasible
/// and matches the existing 32-byte <c>token_hash</c> storage. Only the verifier is ever persisted.
///
/// <see cref="TryComputeVerifier"/> is strict and total: it rejects (returns false, never throws on
/// ordinary malformed input) anything that is not exactly 43 canonical Base64URL characters decoding
/// to exactly 32 bytes, before hashing.
///
/// Memory: temporary raw token byte buffers are best-effort zeroed after use. The Base64URL token is
/// a managed immutable <see cref="string"/> and cannot be reliably zeroed — a documented residual.
/// </summary>
public sealed class Sha256RefreshTokenFactory : IRefreshTokenFactory
{
    private const int TokenByteLength = 32;   // 256-bit
    private const int TokenCharLength = 43;   // unpadded Base64URL of 32 bytes

    public GeneratedRefreshToken Generate()
    {
        var raw = RandomNumberGenerator.GetBytes(TokenByteLength);
        try
        {
            var token = Base64UrlEncode(raw);
            var verifier = SHA256.HashData(raw);
            return new GeneratedRefreshToken(token, verifier);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(raw);
        }
    }

    public bool TryComputeVerifier(string presentedTokenBase64Url, out byte[] verifier)
    {
        verifier = [];

        if (presentedTokenBase64Url is null || presentedTokenBase64Url.Length != TokenCharLength)
        {
            return false;
        }

        // Canonical Base64URL alphabet only — reject '+', '/', '=', whitespace, and any other char.
        foreach (var c in presentedTokenBase64Url)
        {
            if (!(char.IsAsciiLetterOrDigit(c) || c is '-' or '_'))
            {
                return false;
            }
        }

        byte[]? raw = null;
        try
        {
            if (!TryBase64UrlDecode(presentedTokenBase64Url, out raw) || raw!.Length != TokenByteLength)
            {
                return false;
            }

            // Canonical form: re-encoding the decoded bytes must reproduce the input exactly
            // (rejects non-canonical trailing bits).
            if (!string.Equals(Base64UrlEncode(raw), presentedTokenBase64Url, StringComparison.Ordinal))
            {
                return false;
            }

            verifier = SHA256.HashData(raw);
            return true;
        }
        finally
        {
            if (raw is not null)
            {
                CryptographicOperations.ZeroMemory(raw);
            }
        }
    }

    private static string Base64UrlEncode(byte[] data)
        => Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static bool TryBase64UrlDecode(string value, out byte[]? bytes)
    {
        bytes = null;
        var s = value.Replace('-', '+').Replace('_', '/');
        s += (s.Length % 4) switch { 2 => "==", 3 => "=", _ => string.Empty };
        try
        {
            bytes = Convert.FromBase64String(s);
            return true;
        }
        catch (FormatException)
        {
            return false;
        }
    }
}
