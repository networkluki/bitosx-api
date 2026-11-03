using System.Net.Http.Json;
using System.Security.Cryptography;
using BitosX.Application.Email;
using BitosX.Contracts.Accounts;
using BitosX.Infrastructure.Email;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using MySqlConnector;

namespace BitosX.Api.Tests;

/// <summary>
/// Boots the API against the isolated bitosx_test DB with the <b>Login</b> capability enabled
/// (ephemeral JWT signing key + kid) in addition to EmailVerification/EmailDelivery (capturing
/// sender, background dispatcher removed). Used to exercise the full register → verify → login
/// flow end-to-end. Secrets are ephemeral and obviously test-only.
/// </summary>
public sealed class LoginApiFactory : WebApplicationFactory<Program>
{
    internal CapturingEmailSender Emails { get; } = new();

    /// <summary>Passkey security events (the reason behind each generic refusal).</summary>
    internal RecordingPasskeyLog PasskeyLog { get; } = new();

    private readonly string _testDbConnectionString;

    /// <summary>When false the Totp capability is off (no Security:TotpKey): used to prove fail-closed behavior.</summary>
    public bool TotpCapability { get; init; } = true;

    /// <summary>When false the Security:WebAuthn section is blanked (Passkeys capability off: every passkey route is 404).</summary>
    public bool PasskeysCapability { get; init; } = true;

    /// <summary>Overrides the Kestrel endpoint from appsettings.json (for tests that run on a real Kestrel listener).</summary>
    public string? KestrelListenerUrl { get; init; }

    public LoginApiFactory()
    {
        _testDbConnectionString = TestDatabase.ConnectionString;
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Testing");

        builder.UseSetting("ConnectionStrings:Bitosx", _testDbConnectionString);
        builder.UseSetting("Security:EmailVerificationPepper", "test-pepper-" + Convert.ToBase64String(RandomNumberGenerator.GetBytes(24)));
        builder.UseSetting("Security:EmailOutboxKey", Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)));

        // Login capability: current signing key (>=32 bytes) + mandatory kid. Ephemeral per run.
        builder.UseSetting("Security:JwtSigningKey", Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)));
        builder.UseSetting("Security:Jwt:KeyId", "test-k1");
        // Totp capability: key for stored TOTP secrets + recovery-code verifiers. Ephemeral per run.
        if (TotpCapability)
        {
            builder.UseSetting("Security:TotpKey", Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)));
        }

        // Passkeys: the shipped Security:WebAuthn section (RP ID vault.bitosx.se, origin https://vault.bitosx.se) applies
        // unless blanked here.
        if (!PasskeysCapability)
        {
            builder.UseSetting("Security:WebAuthn:RelyingPartyId", "");
            builder.UseSetting("Security:WebAuthn:RelyingPartyName", "");
            builder.UseSetting("Security:WebAuthn:Origins:0", "");
        }

        builder.UseSetting("Security:Argon2:MemoryKiB", "8192");
        builder.UseSetting("Security:Argon2:Iterations", "1");
        builder.UseSetting("Security:Argon2:MaxConcurrency", "2");
        builder.UseSetting("Email:SmtpHost", "smtp.gmail.com");
        builder.UseSetting("Email:SmtpPort", "587");
        builder.UseSetting("Email:SmtpUsername", "test-user");
        builder.UseSetting("Email:SmtpAppPassword", "test-app-password");
        builder.UseSetting("Email:FromAddress", "bitosx@example.com");
        builder.UseSetting("Email:PublicBaseUrl", "https://vault.bitosx.se");
        if (KestrelListenerUrl is not null)
        {
            builder.UseSetting("Kestrel:Endpoints:Http:Url", KestrelListenerUrl);
        }

        builder.ConfigureTestServices(services =>
        {
            services.RemoveAll<IHostedService>();
            services.RemoveAll<IEmailSender>();
            services.AddSingleton<IEmailSender>(Emails);
            services.RemoveAll<BitosX.Application.Passkeys.IPasskeySecurityLog>();
            services.AddSingleton<BitosX.Application.Passkeys.IPasskeySecurityLog>(PasskeyLog);
        });
    }

    public async Task ResetDatabaseAsync()
    {
        Emails.Sent.Clear();
        PasskeyLog.Clear();
        await using var c = new MySqlConnection(_testDbConnectionString);
        await c.OpenAsync();
        await using var cmd = c.CreateCommand();
        // Children first (FKs): refresh_tokens -> sessions -> accounts; outbox references accounts.
        cmd.CommandText = "DELETE FROM webauthn_challenges; DELETE FROM refresh_tokens; DELETE FROM sessions; DELETE FROM email_outbox; DELETE FROM vault_blobs; DELETE FROM accounts;";
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

    public async Task ExecuteAsync(string sql, string paramName, object value)
    {
        await using var c = new MySqlConnection(_testDbConnectionString);
        await c.OpenAsync();
        await using var cmd = c.CreateCommand();
        cmd.CommandText = sql;
        cmd.Parameters.AddWithValue(paramName, value);
        await cmd.ExecuteNonQueryAsync();
    }

    /// <summary>
    /// Registers + verifies an account through the real endpoints and returns its email. The password
    /// is set at verify time (email-first registration). Drives one dispatch to compose the email.
    /// </summary>
    public async Task<string> CreateVerifiedAccountAsync(HttpClient client, string password)
    {
        var email = $"user-{Guid.NewGuid():N}@example.com";

        var register = await client.PostAsJsonAsync("/v1/auth/register", new { email });
        register.EnsureSuccessStatusCode();

        using (var scope = Services.CreateScope())
        {
            await scope.ServiceProvider.GetRequiredService<IEmailOutboxDispatcher>().ProcessDueOnceAsync();
        }

        var token = CapturingEmailSender.ExtractToken(Emails.Sent[^1]);
        var verify = await client.PostAsJsonAsync("/v1/auth/verify-email", new { token, password });
        verify.EnsureSuccessStatusCode();
        return email;
    }

    /// <summary>Logs in through the production endpoint and returns the token pair (starts a session).</summary>
    public static async Task<TokenResponse> LoginAsync(HttpClient client, string email, string password)
    {
        var resp = await client.PostAsJsonAsync("/v1/auth/login", new { email, password });
        resp.EnsureSuccessStatusCode();
        return (await resp.Content.ReadFromJsonAsync<TokenResponse>())!;
    }

    /// <summary>Number of currently-non-revoked sessions for an account (by normalized email).</summary>
    public Task<long> ActiveSessionCountAsync(string email) => QueryScalarAsync<long>(
        "SELECT COUNT(*) FROM sessions s JOIN accounts a ON a.id=s.account_id WHERE a.normalized_email=@e AND s.revoked_at IS NULL",
        "@e", email.ToUpperInvariant());
}
