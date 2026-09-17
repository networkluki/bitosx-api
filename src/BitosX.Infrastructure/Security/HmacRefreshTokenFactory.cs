using System.Security.Cryptography;
using BitosX.Application.Security;

namespace BitosX.Infrastructure.Security;

/// <summary>
/// Generates 256-bit opaque refresh tokens (URL-safe unpadded Base64) and computes their
/// verifier as <c>HMAC-SHA256(pepper, raw 32 token bytes)</c> — the HMAC is over the RAW bytes,
/// never the Base64 text. Only the verifier is ever persisted. Fails closed at construction on
/// invalid pepper material.
///
/// <see cref="TryComputeVerifier"/> is strict and total: it rejects (returns false, never throws
/// on ordinary malformed input) anything that is not exactly 43 canonical Base64URL characters
/// decoding to exactly 32 bytes, before any HMAC work.
///
/// Memory: temporary raw token byte buffers are best-effort zeroed after use. The Base64URL
/// token is a managed immutable <see cref="string"/> and cannot be reliably zeroed — this is a
/// documented residual, not perfect erasure.
/// </summary>
public sealed class HmacRefreshTokenFactory : IRefreshTokenFactory
{
    private const int TokenByteLength = 32;   // 256-bit
    private const int TokenCharLength = 43;   // unpadded Base64URL of 32 bytes

    private readonly byte[] _pepperKey;

    public HmacRefreshTokenFactory(RefreshTokenOptions options)
    {
        // Canonical standard Base64, no whitespace, ≥ 32 decoded bytes; fails closed otherwise.
        // The decoded bytes are the long-lived HMAC key material (not the UTF-8 of the Base64 text).
        _pepperKey = CanonicalBase64Secret.Decode(options.Pepper, "Security:RefreshTokenPepper", minBytes: 32);
    }

    public GeneratedRefreshToken Generate()
    {
        var raw = RandomNumberGenerator.GetBytes(TokenByteLength);
        try
        {
            var token = Base64UrlEncode(raw);
            var verifier = HMACSHA256.HashData(_pepperKey, raw);
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

            verifier = HMACSHA256.HashData(_pepperKey, raw);
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
