namespace BitosX.Application.Accounts;

/// <summary>
/// Lightweight, non-authoritative email syntax check (a single '@', non-empty
/// local/domain, bounded length, no whitespace/control). True validity is proven
/// only by successful verification — no DNS/MX lookup.
/// </summary>
public static class EmailAddressValidator
{
    public const int MaxLength = 320;

    public static bool IsValid(string? email)
    {
        if (string.IsNullOrEmpty(email) || email.Length > MaxLength)
        {
            return false;
        }

        foreach (var c in email)
        {
            if (char.IsWhiteSpace(c) || char.IsControl(c))
            {
                return false;
            }
        }

        var at = email.IndexOf('@');
        if (at <= 0 || at != email.LastIndexOf('@') || at == email.Length - 1)
        {
            return false;
        }

        var domain = email[(at + 1)..];
        return domain.Contains('.') && !domain.StartsWith('.') && !domain.EndsWith('.');
    }
}
