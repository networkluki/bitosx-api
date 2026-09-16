using System.Globalization;

namespace BitosX.Application.Accounts;

/// <summary>
/// Pure email normalization used for uniqueness and lookup. Domain-independent
/// (no persistence or framework dependencies).
/// </summary>
public static class EmailNormalizer
{
    /// <summary>
    /// Normalizes an email for comparison: trims surrounding whitespace and
    /// upper-cases using the invariant culture. Upper-casing (rather than
    /// lower-casing) avoids the Turkish-I problem and matches the common
    /// "normalized" convention. The local-part case is intentionally folded;
    /// BitosX treats addresses case-insensitively for account identity.
    /// </summary>
    /// <exception cref="ArgumentException">Thrown when the email is null/blank.</exception>
    public static string Normalize(string? email)
    {
        if (string.IsNullOrWhiteSpace(email))
        {
            throw new ArgumentException("Email is required.", nameof(email));
        }

        return email.Trim().ToUpperInvariant();
    }
}
