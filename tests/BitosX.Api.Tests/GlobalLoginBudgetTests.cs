using System.Net;
using System.Net.Http.Json;
using System.Text.Json;

namespace BitosX.Api.Tests;

/// <summary>
/// End-to-end tests for the process-wide login budget (2D.2). It runs AFTER the per-IP and per-email
/// limiters, so a request rejected by those never consumes a global token. It is unpartitioned (shared
/// across all IPs and emails), rejects with the generic 429, and is inert when hardening is disabled.
/// </summary>
public sealed class GlobalLoginBudgetTests
{
    private const string ValidPassword = "Correct-Horse-Battery-Staple-1";

    private static int _ip;
    private static string ClientIp() { var n = Interlocked.Increment(ref _ip); return $"10.20.{(n >> 8) & 0xff}.{n & 0xff}"; }
    private static string Email() => $"g-{Guid.NewGuid():N}@example.com";

    private static Task<HttpResponseMessage> LoginAsync(HardenedAuthApiFactory f, string email, string xff)
        => HardenedAuthApiFactory.SendAsync(f.CreateClient(), HttpMethod.Post, "/v1/auth/login", new { email, password = ValidPassword }, "127.0.0.1", xff);

    [Fact]
    public async Task Budget_BurstThenReject_SharedAcrossIpsAndEmails()
    {
        using var f = new HardenedAuthApiFactory();
        f.Overrides["Security:PublicExposureHardening:GlobalLoginBudget:TokenLimit"] = "3";
        f.Overrides["Security:PublicExposureHardening:GlobalLoginBudget:TokensPerPeriod"] = "3";
        f.Overrides["Security:PublicExposureHardening:GlobalLoginBudget:ReplenishmentSeconds"] = "30";
        await f.ResetDatabaseAsync();

        // Each request uses a UNIQUE IP and UNIQUE email, so per-IP and per-email never bind — only the
        // process-wide budget can. The 3-request burst is admitted...
        for (var i = 0; i < 3; i++)
        {
            Assert.NotEqual(HttpStatusCode.TooManyRequests, (await LoginAsync(f, Email(), ClientIp())).StatusCode);
        }

        // ...the 4th (fresh IP + fresh email) is still 429 → the budget is shared across IPs and emails.
        var rejected = await LoginAsync(f, Email(), ClientIp());
        Assert.Equal(HttpStatusCode.TooManyRequests, rejected.StatusCode);
        Assert.NotNull(rejected.Headers.RetryAfter?.Delta);
        using var body = JsonDocument.Parse(await rejected.Content.ReadAsStringAsync());
        Assert.Equal("Too Many Requests", body.RootElement.GetProperty("title").GetString());
    }

    [Fact]
    public async Task PerIpRejection_DoesNotConsumeGlobalToken()
    {
        using var f = new HardenedAuthApiFactory();
        f.Overrides["Security:PublicExposureHardening:LoginPerIp:TokenLimit"] = "1";
        f.Overrides["Security:PublicExposureHardening:LoginPerIp:TokensPerPeriod"] = "1";
        f.Overrides["Security:PublicExposureHardening:GlobalLoginBudget:TokenLimit"] = "2";
        f.Overrides["Security:PublicExposureHardening:GlobalLoginBudget:TokensPerPeriod"] = "2";
        f.Overrides["Security:PublicExposureHardening:GlobalLoginBudget:ReplenishmentSeconds"] = "30";
        await f.ResetDatabaseAsync();

        var ipX = ClientIp();
        Assert.NotEqual(HttpStatusCode.TooManyRequests, (await LoginAsync(f, Email(), ipX)).StatusCode); // global: 1 consumed, 1 left
        Assert.Equal(HttpStatusCode.TooManyRequests, (await LoginAsync(f, Email(), ipX)).StatusCode);     // per-IP reject (before global)

        // If the per-IP rejection had consumed a global token, the budget would be empty and this would be
        // a 429. It is admitted (401 unknown) → the rejected request did not consume a global token.
        var third = await LoginAsync(f, Email(), ClientIp());
        Assert.Equal(HttpStatusCode.Unauthorized, third.StatusCode);
    }

    [Fact]
    public async Task PerEmailRejection_DoesNotConsumeGlobalToken()
    {
        using var f = new HardenedAuthApiFactory();
        f.Overrides["Security:PublicExposureHardening:LoginPerEmail:TokenLimit"] = "1";
        f.Overrides["Security:PublicExposureHardening:LoginPerEmail:TokensPerPeriod"] = "1";
        f.Overrides["Security:PublicExposureHardening:GlobalLoginBudget:TokenLimit"] = "2";
        f.Overrides["Security:PublicExposureHardening:GlobalLoginBudget:TokensPerPeriod"] = "2";
        f.Overrides["Security:PublicExposureHardening:GlobalLoginBudget:ReplenishmentSeconds"] = "30";
        await f.ResetDatabaseAsync();

        var ipX = ClientIp();
        var emailA = Email();
        Assert.NotEqual(HttpStatusCode.TooManyRequests, (await LoginAsync(f, emailA, ipX)).StatusCode); // global: 1 consumed
        Assert.Equal(HttpStatusCode.TooManyRequests, (await LoginAsync(f, emailA, ipX)).StatusCode);     // per-email reject (before global)

        var third = await LoginAsync(f, Email(), ipX); // fresh email → global still has 1 → admitted (401), not 429
        Assert.Equal(HttpStatusCode.Unauthorized, third.StatusCode);
    }

    [Fact]
    public async Task Budget_ReplenishesAfterPeriod()
    {
        using var f = new HardenedAuthApiFactory();
        f.Overrides["Security:PublicExposureHardening:GlobalLoginBudget:TokenLimit"] = "2";
        f.Overrides["Security:PublicExposureHardening:GlobalLoginBudget:TokensPerPeriod"] = "2";
        f.Overrides["Security:PublicExposureHardening:GlobalLoginBudget:ReplenishmentSeconds"] = "1";
        await f.ResetDatabaseAsync();

        for (var i = 0; i < 2; i++)
        {
            await LoginAsync(f, Email(), ClientIp());
        }

        Assert.Equal(HttpStatusCode.TooManyRequests, (await LoginAsync(f, Email(), ClientIp())).StatusCode);
        await Task.Delay(TimeSpan.FromMilliseconds(1300)); // one replenishment period
        Assert.NotEqual(HttpStatusCode.TooManyRequests, (await LoginAsync(f, Email(), ClientIp())).StatusCode);
    }

    [Fact]
    public async Task HardeningDisabled_GlobalBudgetInert()
    {
        using var f = new LoginApiFactory(); // Enabled = false (dev default)
        await f.ResetDatabaseAsync();

        // Far more attempts than any budget would allow; none are throttled because hardening is off.
        for (var i = 0; i < 40; i++)
        {
            var resp = await f.CreateClient().PostAsJsonAsync("/v1/auth/login", new { email = Email(), password = ValidPassword });
            Assert.NotEqual(HttpStatusCode.TooManyRequests, resp.StatusCode);
            Assert.NotEqual(HttpStatusCode.ServiceUnavailable, resp.StatusCode);
        }
    }
}
