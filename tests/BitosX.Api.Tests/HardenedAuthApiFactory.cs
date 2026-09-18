using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using BitosX.Application.Email;
using BitosX.Infrastructure.Email;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using MySqlConnector;

namespace BitosX.Api.Tests;

/// <summary>
/// Test-only front middleware that sets the connection's RemoteIpAddress from the <c>X-Test-Peer-Ip</c>
/// header (defaulting to loopback), simulating the TCP peer Kestrel sees. It runs BEFORE the real
/// UseForwardedHeaders, so the production forwarded-header trust chain (loopback proxy only) is exercised
/// deterministically. There is no such middleware in production.
/// </summary>
internal sealed class TestPeerIpStartupFilter : IStartupFilter
{
    public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app =>
    {
        app.Use(async (ctx, n) =>
        {
            var peer = ctx.Request.Headers["X-Test-Peer-Ip"].ToString();
            ctx.Connection.RemoteIpAddress = string.IsNullOrEmpty(peer) ? IPAddress.Loopback : IPAddress.Parse(peer);
            await n();
        });
        next(app);
    };
}

/// <summary>
/// Boots the API against bitosx_test with the Login capability AND Phase 2D public-exposure hardening
/// enabled (rate limiters active). Allows deterministic per-request client-IP control via the
/// <c>X-Test-Peer-Ip</c> / <c>X-Forwarded-For</c> headers. Per-policy overrides may be supplied (e.g. a
/// short replenishment period) without weakening production defaults.
/// </summary>
public sealed class HardenedAuthApiFactory : WebApplicationFactory<Program>
{
    internal CapturingEmailSender Emails { get; } = new();

    private readonly string _testDbConnectionString;

    /// <summary>Per-instance config overrides, applied over the hardened defaults. Set before the first client.</summary>
    public IDictionary<string, string?> Overrides { get; } = new Dictionary<string, string?>();

    public HardenedAuthApiFactory()
    {
        var cfg = new ConfigurationBuilder().AddUserSecrets("bitosx-infrastructure-tests").Build();
        _testDbConnectionString = cfg.GetConnectionString("BitosxTest")
            ?? throw new InvalidOperationException("ConnectionStrings:BitosxTest not configured for tests.");
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Testing");

        builder.UseSetting("ConnectionStrings:Bitosx", _testDbConnectionString);
        builder.UseSetting("Security:EmailVerificationPepper", "test-pepper-" + Convert.ToBase64String(RandomNumberGenerator.GetBytes(24)));
        builder.UseSetting("Security:EmailOutboxKey", Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)));
        builder.UseSetting("Security:JwtSigningKey", Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)));
        builder.UseSetting("Security:Jwt:KeyId", "test-k1");
        builder.UseSetting("Security:Argon2:MemoryKiB", "8192");
        builder.UseSetting("Security:Argon2:Iterations", "1");
        builder.UseSetting("Security:Argon2:MaxConcurrency", "2");
        builder.UseSetting("Email:SmtpHost", "smtp.gmail.com");
        builder.UseSetting("Email:SmtpPort", "587");
        builder.UseSetting("Email:SmtpUsername", "test-user");
        builder.UseSetting("Email:SmtpAppPassword", "test-app-password");
        builder.UseSetting("Email:FromAddress", "bitosx@example.com");
        builder.UseSetting("Email:PublicBaseUrl", "https://vault.bitosx.se");

        // Hardening ON (rate limiters active).
        builder.UseSetting("Security:PublicExposureHardening:Enabled", "true");
        foreach (var kv in Overrides)
        {
            builder.UseSetting(kv.Key, kv.Value);
        }

        builder.ConfigureTestServices(services =>
        {
            services.RemoveAll<IHostedService>();
            services.RemoveAll<IEmailSender>();
            services.AddSingleton<IEmailSender>(Emails);
            services.AddSingleton<IStartupFilter, TestPeerIpStartupFilter>();
        });
    }

    public async Task ResetDatabaseAsync()
    {
        Emails.Sent.Clear();
        await using var c = new MySqlConnection(_testDbConnectionString);
        await c.OpenAsync();
        await using var cmd = c.CreateCommand();
        cmd.CommandText = "DELETE FROM refresh_tokens; DELETE FROM sessions; DELETE FROM email_outbox; DELETE FROM accounts;";
        await cmd.ExecuteNonQueryAsync();
    }

    /// <summary>Registers + verifies an account through the real endpoints (from a trusted loopback peer).</summary>
    public async Task<string> CreateVerifiedAccountAsync(string password)
    {
        var client = CreateClient();
        var email = $"user-{Guid.NewGuid():N}@example.com";

        // Setup calls come from the trusted loopback proxy with a forwarded client IP, so they are not
        // starved by the per-IP/per-email limiters intended for the tests themselves.
        (await SendAsync(client, HttpMethod.Post, "/v1/auth/register", new { email }, peerIp: "127.0.0.1", forwardedFor: "10.0.0.1")).EnsureSuccessStatusCode();

        using (var scope = Services.CreateScope())
        {
            await scope.ServiceProvider.GetRequiredService<IEmailOutboxDispatcher>().ProcessDueOnceAsync();
        }

        var token = CapturingEmailSender.ExtractToken(Emails.Sent[^1]);
        (await SendAsync(client, HttpMethod.Post, "/v1/auth/verify-email", new { token, password }, peerIp: "127.0.0.1", forwardedFor: "10.0.0.1")).EnsureSuccessStatusCode();
        return email;
    }

    /// <summary>Sends a JSON request with a simulated TCP peer and optional X-Forwarded-For client IP.</summary>
    public static async Task<HttpResponseMessage> SendAsync(
        HttpClient client, HttpMethod method, string path, object? body, string? peerIp = null, string? forwardedFor = null)
    {
        using var request = new HttpRequestMessage(method, path);
        if (body is not null)
        {
            request.Content = JsonContent.Create(body);
        }

        if (peerIp is not null)
        {
            request.Headers.TryAddWithoutValidation("X-Test-Peer-Ip", peerIp);
        }

        if (forwardedFor is not null)
        {
            request.Headers.TryAddWithoutValidation("X-Forwarded-For", forwardedFor);
        }

        return await client.SendAsync(request);
    }
}
