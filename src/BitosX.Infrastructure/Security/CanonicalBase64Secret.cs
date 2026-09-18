using System.Security.Cryptography;

namespace BitosX.Infrastructure.Security;

/// <summary>
/// Parses a secret configured as canonical STANDARD Base64: no whitespace anywhere, an exact
/// canonical round-trip, and a minimum decoded length. Fails closed
/// (<see cref="InvalidOperationException"/>) on anything else — malformed/non-canonical secret
/// configuration is an operator error, never silently trimmed or normalized. Internal to
/// Infrastructure so secret parsing is never exposed through the Application layer.
///
/// The returned bytes are the intended long-lived HMAC/signing key material owned by the caller
/// and are NOT zeroed here; temporary buffers created only to reject invalid input are best-effort
/// zeroed before throwing.
/// </summary>
internal static class CanonicalBase64Secret
{
    public static byte[] Decode(string? value, string name, int minBytes)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new InvalidOperationException($"{name} is required.");
        }

        foreach (var c in value)
        {
            if (char.IsWhiteSpace(c))
            {
                throw new InvalidOperationException($"{name} must be canonical Base64 with no whitespace.");
            }
        }

        byte[] decoded;
        try
        {
            decoded = Convert.FromBase64String(value);
        }
        catch (FormatException)
        {
            throw new InvalidOperationException($"{name} must be valid standard Base64.");
        }

        if (decoded.Length < minBytes)
        {
            CryptographicOperations.ZeroMemory(decoded);
            throw new InvalidOperationException($"{name} must decode to at least {minBytes} bytes.");
        }

        if (!string.Equals(Convert.ToBase64String(decoded), value, StringComparison.Ordinal))
        {
            CryptographicOperations.ZeroMemory(decoded);
            throw new InvalidOperationException($"{name} must be canonical Base64 (non-canonical representation rejected).");
        }

        return decoded;
    }
}
