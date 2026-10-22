using BitosX.Application.Email;

namespace BitosX.Application.Verification;

/// <summary>Builds the plain-text + HTML emails that carry a fragment-based token link.</summary>
public interface IVerificationEmailComposer
{
    /// <summary>Email-verification message (activate account + choose the first password).</summary>
    EmailMessage Compose(string toAddress, string tokenBase64Url, DateTime expiresAtUtc, int expiresInMinutes);

    /// <summary>Password-reset message (choose a new account password; all sessions are signed out).</summary>
    EmailMessage ComposePasswordReset(string toAddress, string tokenBase64Url, DateTime expiresAtUtc, int expiresInMinutes);
}

public sealed class VerificationEmailComposer : IVerificationEmailComposer
{
    private readonly EmailOptions _options;

    public VerificationEmailComposer(EmailOptions options) => _options = options;

    public EmailMessage Compose(string toAddress, string tokenBase64Url, DateTime expiresAtUtc, int expiresInMinutes)
    {
        var link = FragmentLink(_options.VerificationPath, tokenBase64Url);

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

    public EmailMessage ComposePasswordReset(string toAddress, string tokenBase64Url, DateTime expiresAtUtc, int expiresInMinutes)
    {
        var link = FragmentLink(_options.PasswordResetPath, tokenBase64Url);

        const string subject = "Reset your BitosX account password";

        var text =
            $"""
            BitosX — password reset

            Someone (hopefully you) asked to reset the account password for this email
            address. To choose a new password, open the link below. This link expires in
            {expiresInMinutes} minutes and can be used once. Every signed-in device is
            signed out when the password changes.

            {link}

            This resets only the account password used to sign in. It cannot recover or
            change your vault master password: the vault stays encrypted with the master
            password you chose, and BitosX never has it.

            If you did not request a reset, you can safely ignore this email; your
            password stays as it is.
            """;

        var html =
            $"""
            <!doctype html><html><body style="font-family:system-ui,Arial,sans-serif">
            <h2>BitosX — password reset</h2>
            <p>Someone (hopefully you) asked to reset the account password for this email
            address. To choose a new password, open the link below. This link expires in
            <strong>{expiresInMinutes} minutes</strong> and can be used once. Every signed-in
            device is signed out when the password changes.</p>
            <p><a href="{link}">Choose a new account password</a></p>
            <p>This resets only the account password used to sign in. It cannot recover or
            change your vault master password: the vault stays encrypted with the master
            password you chose, and BitosX never has it.</p>
            <p style="color:#666">If you did not request a reset, you can safely ignore this email;
            your password stays as it is.</p>
            </body></html>
            """;

        return new EmailMessage(toAddress, subject, text, html);
    }

    // Token goes in the URL fragment (#) so it is never sent to the web server.
    private string FragmentLink(string path, string tokenBase64Url)
    {
        var baseUrl = _options.PublicBaseUrl.TrimEnd('/');
        var normalizedPath = path.StartsWith('/') ? path : "/" + path;
        return $"{baseUrl}{normalizedPath}#token={tokenBase64Url}";
    }
}
