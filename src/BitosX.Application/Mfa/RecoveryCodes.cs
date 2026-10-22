using System.Security.Cryptography;

namespace BitosX.Application.Mfa;

/// <summary>
/// Single-use recovery codes: 10 characters from an alphabet without look-alikes (no 0/O, 1/I/L),
/// shown as <c>xxxxx-xxxxx</c>, about 49 bits of entropy each. Only a keyed verifier is stored.
/// </summary>
public static class RecoveryCodes
{
    public const string Alphabet = "abcdefghjkmnpqrstuvwxyz23456789";
    public const int Length = 10;

    public static string Generate()
    {
        var chars = new char[Length];
        for (var i = 0; i < Length; i++)
        {
            chars[i] = Alphabet[RandomNumberGenerator.GetInt32(Alphabet.Length)];
        }

        return new string(chars, 0, 5) + "-" + new string(chars, 5, 5);
    }

    /// <summary>
    /// Lower-cases and strips separators/whitespace; returns null unless the result is exactly
    /// <see cref="Length"/> alphabet characters. The canonical form is what is hashed.
    /// </summary>
    public static string? Canonicalize(string? code)
    {
        if (string.IsNullOrEmpty(code) || code.Length > 32) return null;
        var chars = new List<char>(Length);
        foreach (var raw in code)
        {
            if (raw is '-' or ' ' or '\t') continue;
            var c = char.ToLowerInvariant(raw);
            if (Alphabet.IndexOf(c) < 0) return null;
            chars.Add(c);
            if (chars.Count > Length) return null;
        }

        return chars.Count == Length ? new string(chars.ToArray()) : null;
    }
}
