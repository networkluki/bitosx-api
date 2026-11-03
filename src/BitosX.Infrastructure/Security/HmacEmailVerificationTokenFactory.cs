using System.Security.Cryptography;
using System.Text;
using BitosX.Application.Verification;

namespace BitosX.Infrastructure.Security;

/// <summary>
/// Generates 256-bit tokens (URL-safe Base64) and computes
/// <c>HMAC-SHA256(pepper, token)</c> verifiers. The pepper key is the UTF-8
/// bytes of the configured secret string.
/// </summary>
public sealed class HmacEmailVerificationTokenFactory : IEmailVerificationTokenFactory
{
    private const int TokenBytes = 32; // 256-bit

    private readonly byte[] _pepperKey;

    public HmacEmailVerificationTokenFactory(EmailVerificationSecurityOptions options)
    {
        if (string.IsNullOrEmpty(options.Pepper))
        {
            throw new InvalidOperationException("EmailVerification pepper is not configured.");
        }

        _pepperKey = Encoding.UTF8.GetBytes(options.Pepper);
    }

    public GeneratedToken GenerateToken()
    {
        var tokenBytes = RandomNumberGenerator.GetBytes(TokenBytes);
        var tokenB64Url = Base64UrlEncode(tokenBytes);
        var verifier = HMACSHA256.HashData(_pepperKey, tokenBytes);
        return new GeneratedToken(tokenB64Url, verifier);
    }

    public byte[] ComputeVerifier(string tokenBase64Url)
    {
        var tokenBytes = Base64UrlDecode(tokenBase64Url);
        return HMACSHA256.HashData(_pepperKey, tokenBytes);
    }

    private static string Base64UrlEncode(byte[] data)
        => Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static byte[] Base64UrlDecode(string? value)
    {
        if (string.IsNullOrEmpty(value))
        {
            throw new FormatException("Missing Base64Url token."); // callers map FormatException to "invalid token"
        }

        var s = value.Replace('-', '+').Replace('_', '/');
        var padded = (s.Length % 4) switch
        {
            2 => s + "==",
            3 => s + "=",
            0 => s,
            _ => throw new FormatException("Invalid Base64Url token."),
        };
        return Convert.FromBase64String(padded);
    }
}
