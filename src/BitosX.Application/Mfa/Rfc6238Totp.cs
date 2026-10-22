using System.Buffers.Binary;
using System.Security.Cryptography;

namespace BitosX.Application.Mfa;

/// <summary>
/// RFC 6238 time-based one-time passwords over RFC 4226 HOTP with HMAC-SHA1 (the algorithm every
/// authenticator app implements). Pure functions; the caller supplies the time and the accepted
/// window and enforces replay protection by remembering the highest accepted step.
/// </summary>
public static class Rfc6238Totp
{
    /// <summary>The time step for a Unix time (seconds), RFC 6238 §4.2 with T0 = 0.</summary>
    public static long Step(long unixSeconds, int periodSeconds) => unixSeconds / periodSeconds;

    /// <summary>The code for one step, zero-padded to <paramref name="digits"/>.</summary>
    public static string Compute(ReadOnlySpan<byte> secret, long step, int digits)
    {
        Span<byte> counter = stackalloc byte[8];
        BinaryPrimitives.WriteInt64BigEndian(counter, step);
        Span<byte> mac = stackalloc byte[20];
        HMACSHA1.HashData(secret, counter, mac);
        var offset = mac[19] & 0x0F;
        var binary = ((mac[offset] & 0x7F) << 24) | (mac[offset + 1] << 16) | (mac[offset + 2] << 8) | mac[offset + 3];
        var modulus = (int)Math.Pow(10, digits);
        return (binary % modulus).ToString().PadLeft(digits, '0');
    }

    /// <summary>
    /// True when <paramref name="code"/> matches a step within ±<paramref name="windowSteps"/> of the
    /// current one, comparing in constant time per candidate and skipping steps at or below
    /// <paramref name="lastUsedStep"/> (a code is accepted once, and never one older than the last
    /// accepted). <paramref name="matchedStep"/> is the step to record as used.
    /// </summary>
    public static bool TryMatch(
        ReadOnlySpan<byte> secret, string code, long unixSeconds, int digits, int periodSeconds, int windowSteps,
        long? lastUsedStep, out long matchedStep)
    {
        matchedStep = 0;
        if (!IsDigits(code, digits)) return false;

        var current = Step(unixSeconds, periodSeconds);
        var found = false;
        for (var offset = -windowSteps; offset <= windowSteps; offset++)
        {
            var step = current + offset;
            if (lastUsedStep is { } used && step <= used) continue;
            var candidate = Compute(secret, step, digits);
            // Evaluate every candidate; never break early on a match (timing).
            if (CryptographicOperations.FixedTimeEquals(System.Text.Encoding.ASCII.GetBytes(candidate), System.Text.Encoding.ASCII.GetBytes(code)) && !found)
            {
                found = true;
                matchedStep = step;
            }
        }

        return found;
    }

    public static bool IsDigits(string? code, int digits)
    {
        if (code is null || code.Length != digits) return false;
        foreach (var c in code)
        {
            if (c is < '0' or > '9') return false;
        }

        return true;
    }
}
