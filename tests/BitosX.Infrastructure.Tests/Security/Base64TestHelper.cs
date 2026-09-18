namespace BitosX.Infrastructure.Tests.Security;

internal static class Base64TestHelper
{
    private const string StandardAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    /// <summary>
    /// Finds a single-character mutation of <paramref name="canonical"/> that decodes to the SAME
    /// bytes but is NOT the canonical Base64 of those bytes (e.g. non-zero trailing bits). Such a
    /// form exists for keys whose length leaves unused low bits in the final data char.
    /// </summary>
    public static bool TryMakeNonCanonical(string canonical, out string nonCanonical)
    {
        nonCanonical = string.Empty;
        var bytes = Convert.FromBase64String(canonical);
        for (var i = 0; i < canonical.Length; i++)
        {
            if (canonical[i] == '=')
            {
                continue;
            }

            foreach (var c in StandardAlphabet)
            {
                if (c == canonical[i])
                {
                    continue;
                }

                var candidate = canonical[..i] + c + canonical[(i + 1)..];
                byte[] decoded;
                try
                {
                    decoded = Convert.FromBase64String(candidate);
                }
                catch (FormatException)
                {
                    continue;
                }

                if (decoded.AsSpan().SequenceEqual(bytes)
                    && !string.Equals(Convert.ToBase64String(decoded), candidate, StringComparison.Ordinal))
                {
                    nonCanonical = candidate;
                    return true;
                }
            }
        }

        return false;
    }
}
