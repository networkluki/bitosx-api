namespace BitosX.Application.Versioning;

/// <summary>
/// Pure helpers for producing a clean, non-sensitive product version string.
/// </summary>
public static class ProductVersion
{
    /// <summary>Fallback used when no version metadata is available.</summary>
    public const string Unknown = "0.0.0";

    /// <summary>
    /// Normalizes a raw assembly informational version into a clean value safe
    /// for public exposure: trims whitespace and drops SemVer build metadata
    /// (everything from the first '+'). Prerelease labels are preserved.
    /// </summary>
    public static string Normalize(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
        {
            return Unknown;
        }

        var trimmed = raw.Trim();

        var plusIndex = trimmed.IndexOf('+');
        if (plusIndex >= 0)
        {
            trimmed = trimmed[..plusIndex];
        }

        return trimmed.Length == 0 ? Unknown : trimmed;
    }
}
