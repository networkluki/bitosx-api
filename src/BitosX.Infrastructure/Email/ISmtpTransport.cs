using MailKit.Security;
using MimeKit;

namespace BitosX.Infrastructure.Email;

/// <summary>
/// Thin abstraction over the SMTP client operations, so the overall-attempt-deadline
/// behavior can be tested without a real network (a fake can stall a given operation).
/// </summary>
public interface ISmtpTransport : IAsyncDisposable
{
    int Timeout { get; set; }
    Task ConnectAsync(string host, int port, SecureSocketOptions options, CancellationToken cancellationToken);
    Task AuthenticateAsync(string username, string password, CancellationToken cancellationToken);
    Task SendAsync(MimeMessage message, CancellationToken cancellationToken);
    Task DisconnectAsync(bool quit, CancellationToken cancellationToken);
}

/// <summary>Creates a fresh transport per send attempt.</summary>
public interface ISmtpTransportFactory
{
    ISmtpTransport Create();
}
