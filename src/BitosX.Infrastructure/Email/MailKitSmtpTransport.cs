using MailKit.Net.Smtp;
using MailKit.Security;
using MimeKit;

namespace BitosX.Infrastructure.Email;

/// <summary>MailKit-backed <see cref="ISmtpTransport"/>.</summary>
public sealed class MailKitSmtpTransport : ISmtpTransport
{
    private readonly SmtpClient _client = new();

    public int Timeout { get => _client.Timeout; set => _client.Timeout = value; }

    public Task ConnectAsync(string host, int port, SecureSocketOptions options, CancellationToken ct)
        => _client.ConnectAsync(host, port, options, ct);

    public Task AuthenticateAsync(string username, string password, CancellationToken ct)
        => _client.AuthenticateAsync(username, password, ct);

    public Task SendAsync(MimeMessage message, CancellationToken ct)
        => _client.SendAsync(message, ct);

    public Task DisconnectAsync(bool quit, CancellationToken ct)
        => _client.DisconnectAsync(quit, ct);

    public async ValueTask DisposeAsync()
    {
        _client.Dispose();
        await ValueTask.CompletedTask;
    }
}

public sealed class MailKitSmtpTransportFactory : ISmtpTransportFactory
{
    public ISmtpTransport Create() => new MailKitSmtpTransport();
}
