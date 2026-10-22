namespace BitosX.Application.Email;

/// <summary>Non-secret email configuration (sender identity + verification link base).</summary>
public sealed class EmailOptions
{
    public string FromAddress { get; set; } = string.Empty;
    public string FromName { get; set; } = "BitosX";

    /// <summary>Public base URL for the verification page (config-driven; e.g. https://vault.bitosx.se).</summary>
    public string PublicBaseUrl { get; set; } = string.Empty;

    /// <summary>Path of the verification page; the token is placed in the URL fragment.</summary>
    public string VerificationPath { get; set; } = "/verify-email";

    /// <summary>Path of the password-reset page; the token is placed in the URL fragment.</summary>
    public string PasswordResetPath { get; set; } = "/reset-password";
}
