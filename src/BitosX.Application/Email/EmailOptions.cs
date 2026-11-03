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

    /// <summary>
    /// Fail-closed check of <see cref="PublicBaseUrl"/>, run at startup whenever EmailVerification is enabled:
    /// every verification and reset email links to it, and an empty or relative value would mail dead links.
    /// It must be an absolute <c>https://host[:port]</c> origin (an optional trailing <c>/</c>; no path, query,
    /// fragment or userinfo). <c>http://</c> is accepted only for a loopback host (<c>localhost</c>,
    /// <c>127.0.0.1</c>, <c>[::1]</c>) and only when <paramref name="allowLoopbackHttp"/> is set (Development/Testing).
    /// </summary>
    public void ValidatePublicBaseUrl(bool allowLoopbackHttp)
    {
        const string key = "Email:PublicBaseUrl";
        if (string.IsNullOrWhiteSpace(PublicBaseUrl) || !Uri.TryCreate(PublicBaseUrl, UriKind.Absolute, out var uri))
        {
            throw new InvalidOperationException($"{key} must be set to the absolute https:// URL of the web app (e.g. https://vault.bitosx.se) when email verification is enabled.");
        }

        var https = string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.Ordinal);
        var loopbackHttp = allowLoopbackHttp
            && string.Equals(uri.Scheme, Uri.UriSchemeHttp, StringComparison.Ordinal)
            && (uri.IsLoopback || string.Equals(uri.Host, "localhost", StringComparison.OrdinalIgnoreCase));
        if (!https && !loopbackHttp)
        {
            throw new InvalidOperationException($"{key} must be an https:// URL (http:// only for a loopback host in Development/Testing).");
        }

        if (uri.UserInfo.Length > 0 || uri.Query.Length > 0 || uri.Fragment.Length > 0 || (uri.AbsolutePath != "/" && uri.AbsolutePath.Length > 0)
            || PublicBaseUrl.Contains('?') || PublicBaseUrl.Contains('#'))
        {
            throw new InvalidOperationException($"{key} must be an origin only (scheme, host, optional port), without userinfo, path, query or fragment.");
        }
    }
}
