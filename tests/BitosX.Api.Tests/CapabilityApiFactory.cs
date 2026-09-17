using System.Security.Cryptography;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using MySqlConnector;

namespace BitosX.Api.Tests;

/// <summary>
/// Boots the API against bitosx_test with a chosen capability set, by controlling which
/// secrets are present. No SMTP credentials are ever set here (EmailDelivery stays off),
/// so no dispatcher/sender is registered and no real mail is attempted.
/// </summary>
public sealed class CapabilityApiFactory : WebApplicationFactory<Program>
{
    private readonly bool _verification;
    private readonly string _testDbConnectionString;

    public CapabilityApiFactory(bool verification)
    {
        _verification = verification;
        var cfg = new Microsoft.Extensions.Configuration.ConfigurationBuilder()
            .AddUserSecrets("bitosx-infrastructure-tests").Build();
        _testDbConnectionString = cfg.GetConnectionString("BitosxTest")
            ?? throw new InvalidOperationException("ConnectionStrings:BitosxTest not configured for tests.");
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Testing");
        builder.UseSetting("ConnectionStrings:Bitosx", _testDbConnectionString);
        builder.UseSetting("Security:Argon2:MemoryKiB", "8192");
        builder.UseSetting("Security:Argon2:Iterations", "1");
        builder.UseSetting("Security:Argon2:MaxConcurrency", "1");
        builder.UseSetting("Email:FromAddress", "bitosx@example.com");
        builder.UseSetting("Email:PublicBaseUrl", "https://vault.bitosx.se");
        if (_verification)
        {
            builder.UseSetting("Security:EmailVerificationPepper", "test-pepper-" + Convert.ToBase64String(RandomNumberGenerator.GetBytes(24)));
            builder.UseSetting("Security:EmailOutboxKey", Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)));
        }
        // Deliberately NO Email:SmtpUsername / Email:SmtpAppPassword → EmailDelivery disabled.
    }

    public async Task ResetDatabaseAsync()
    {
        await using var c = new MySqlConnection(_testDbConnectionString);
        await c.OpenAsync();
        await using var cmd = c.CreateCommand();
        cmd.CommandText = "DELETE FROM email_outbox; DELETE FROM accounts;";
        await cmd.ExecuteNonQueryAsync();
    }

    public async Task<long> CountAsync(string sql)
    {
        await using var c = new MySqlConnection(_testDbConnectionString);
        await c.OpenAsync();
        await using var cmd = c.CreateCommand();
        cmd.CommandText = sql;
        return Convert.ToInt64(await cmd.ExecuteScalarAsync());
    }
}
