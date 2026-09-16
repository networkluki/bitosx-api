namespace BitosX.Application.Accounts;

/// <summary>Outcome of validating an account password against policy.</summary>
public enum PasswordPolicyResult
{
    Valid,
    TooShort,
    TooLong,
}

/// <summary>
/// Account-password policy: 12–128 characters, used exactly as supplied.
/// No trimming, case folding, Unicode normalization, or composition rules —
/// the exact string the user supplies defines the credential.
/// </summary>
public static class AccountPasswordPolicy
{
    public const int MinLength = 12;
    public const int MaxLength = 128;

    public static PasswordPolicyResult Validate(string? password)
    {
        var length = password?.Length ?? 0;
        if (length < MinLength)
        {
            return PasswordPolicyResult.TooShort;
        }

        return length > MaxLength ? PasswordPolicyResult.TooLong : PasswordPolicyResult.Valid;
    }
}
