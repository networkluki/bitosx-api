using System.Security.Cryptography;
using BitosX.Application.Email;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using MySqlConnector;

namespace BitosX.Api.Tests;

/// <summary>Captures composed emails instead of sending them.</summary>
internal sealed class CapturingEmailSender : IEmailSender
{
    public List<EmailMessage> Sent { get; } = [];
    public EmailSendResult Result { get; set; } = EmailSendResult.Sent;

    public Task<EmailSendResult> SendAsync(EmailMessage message, CancellationToken ct = default)
    {
        if (Result == EmailSendResult.Sent) Sent.Add(message);
        return Task.FromResult(Result);
    }

    public static string ExtractToken(EmailMessage m)
    {
        const string marker = "#token=";
        var i = m.TextBody.IndexOf(marker, StringComparison.Ordinal);
        var start = i + marker.Length;
        var end = start;
        while (end < m.TextBody.Length && !char.IsWhiteSpace(m.TextBody[end])) end++;
        return m.TextBody[start..end];
    }
}

/// <summary>
/// Boots the API against the isolated bitosx_test DB (via the test_app account),
/// with a capturing email sender and the background dispatcher removed (tests
/// drive the dispatcher explicitly). Ephemeral test pepper/key/Argon2 params.
/// </summary>
public sealed class AuthApiFactory : WebApplicationFactory<Program>
{
    internal CapturingEmailSender Emails { get; } = new();

    private readonly string _testDbConnectionString;

    public AuthApiFactory()
    {
        _testDbConnectionString = TestDatabase.ConnectionString;
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Testing"); // avoids loading the API's real user-secrets

        // UseSetting values are visible to WebApplication.CreateBuilder's configuration
        // BEFORE Program reads it (ConfigureAppConfiguration would apply too late).
        builder.UseSetting("ConnectionStrings:Bitosx", _testDbConnectionString);
        builder.UseSetting("Security:EmailVerificationPepper", "test-pepper-" + Convert.ToBase64String(RandomNumberGenerator.GetBytes(24)));
        builder.UseSetting("Security:EmailOutboxKey", Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)));
        builder.UseSetting("Security:Argon2:MemoryKiB", "8192");
        builder.UseSetting("Security:Argon2:Iterations", "1");
        builder.UseSetting("Security:Argon2:MaxConcurrency", "2");
        builder.UseSetting("Email:SmtpHost", "smtp.gmail.com");
        builder.UseSetting("Email:SmtpPort", "587");
        builder.UseSetting("Email:SmtpUsername", "test-user");
        builder.UseSetting("Email:SmtpAppPassword", "test-app-password");
        builder.UseSetting("Email:FromAddress", "bitosx@example.com");
        builder.UseSetting("Email:PublicBaseUrl", "https://vault.bitosx.se");

        builder.ConfigureTestServices(services =>
        {
            services.RemoveAll<IHostedService>();       // no auto-dispatch during tests
            services.RemoveAll<IEmailSender>();
            services.AddSingleton<IEmailSender>(Emails); // capturing sender
        });
    }

    public async Task ResetDatabaseAsync()
    {
        Emails.Sent.Clear();
        await using var c = new MySqlConnection(_testDbConnectionString);
        await c.OpenAsync();
        await using var cmd = c.CreateCommand();
        cmd.CommandText = "DELETE FROM email_outbox; DELETE FROM accounts;";
        await cmd.ExecuteNonQueryAsync();
    }

    public async Task<T> QueryScalarAsync<T>(string sql, string paramName, object value)
    {
        await using var c = new MySqlConnection(_testDbConnectionString);
        await c.OpenAsync();
        await using var cmd = c.CreateCommand();
        cmd.CommandText = sql;
        cmd.Parameters.AddWithValue(paramName, value);
        var result = await cmd.ExecuteScalarAsync();
        return (T)Convert.ChangeType(result!, typeof(T));
    }
}
