using BitosX.Application.Email;

namespace BitosX.Application.Verification;

/// <summary>Builds the plain-text + HTML verification email (fragment-based link).</summary>
public interface IVerificationEmailComposer
{
    EmailMessage Compose(string toAddress, string tokenBase64Url, DateTime expiresAtUtc, int expiresInMinutes);
}

public sealed class VerificationEmailComposer : IVerificationEmailComposer
{
    private readonly EmailOptions _options;

    public VerificationEmailComposer(EmailOptions options) => _options = options;

    public EmailMessage Compose(string toAddress, string tokenBase64Url, DateTime expiresAtUtc, int expiresInMinutes)
    {
        // Token goes in the URL fragment (#) so it is never sent to the web server.
        var baseUrl = _options.PublicBaseUrl.TrimEnd('/');
        var path = _options.VerificationPath.StartsWith('/') ? _options.VerificationPath : "/" + _options.VerificationPath;
        var link = $"{baseUrl}{path}#token={tokenBase64Url}";

        const string subject = "Verify your BitosX account email";

        var text =
            $"""
            BitosX — email verification

            Someone (hopefully you) started creating a BitosX account with this email
            address. To finish, open the link below and choose your account password.
            This link expires in {expiresInMinutes} minutes.

            {link}

            If you did not request a BitosX account, you can safely ignore this email.
            """;

        var html =
            $"""
            <!doctype html><html><body style="font-family:system-ui,Arial,sans-serif">
            <h2>BitosX — email verification</h2>
            <p>Someone (hopefully you) started creating a BitosX account with this email
            address. To finish, open the link below and choose your account password.
            This link expires in <strong>{expiresInMinutes} minutes</strong>.</p>
            <p><a href="{link}">Verify my email and set my password</a></p>
            <p style="color:#666">If you did not request a BitosX account, you can safely ignore this email.</p>
            </body></html>
            """;

        return new EmailMessage(toAddress, subject, text, html);
    }
}
