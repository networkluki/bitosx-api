using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using BitosX.Contracts.Accounts;
using BitosX.Contracts.Sync;

namespace BitosX.Api.Tests;

/// <summary>
/// The per-account envelope write limiter (SyncWritePerAccount, 30 burst) over HTTP in hardened mode: uploads and
/// deletes share the bucket, the 31st write is a 429 with Retry-After, the limit is per account, and — the point
/// of running it as middleware — a rejected request is refused BEFORE its body is read or parsed.
/// </summary>
public sealed class SyncRateLimitTests : IClassFixture<HardenedAuthApiFactory>, IAsyncLifetime
{
    private const string Password = "Correct-Horse-Battery-Staple-1";
    private static readonly string Envelope = Convert.ToBase64String("{\"version\":1,\"ciphertext\":\"AAAA\"}"u8.ToArray());

    private readonly HardenedAuthApiFactory _factory;
    private static int _ipCounter = 50_000;
    private static string ClientIp() { var n = Interlocked.Increment(ref _ipCounter); return $"10.{(n >> 16) & 0xff}.{(n >> 8) & 0xff}.{n & 0xff}"; }

    public SyncRateLimitTests(HardenedAuthApiFactory factory) => _factory = factory;

    public async Task InitializeAsync() => await _factory.ResetDatabaseAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    private async Task<HttpClient> SignedInAsync()
    {
        var email = await _factory.CreateVerifiedAccountAsync(Password);
        var login = await HardenedAuthApiFactory.SendAsync(_factory.CreateClient(), HttpMethod.Post, "/v1/auth/login", new { email, password = Password }, "127.0.0.1", ClientIp());
        login.EnsureSuccessStatusCode();
        var tokens = (await login.Content.ReadFromJsonAsync<TokenResponse>())!;
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tokens.AccessToken);
        return client;
    }

    [Fact]
    public async Task UploadsAndDeletes_ShareThePerAccountBucket_The31stWriteIs429_OtherAccountsUnaffected()
    {
        var client = await SignedInAsync();
        long revision = 0;
        for (var i = 0; i < 30; i++)
        {
            if (i % 3 == 2)
            {
                Assert.Equal(HttpStatusCode.NoContent, (await client.DeleteAsync("/v1/sync/envelope")).StatusCode);
                revision = 0;
                continue;
            }

            var resp = await client.PutAsJsonAsync("/v1/sync/envelope", new { baseRevision = revision, envelope = Envelope });
            Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
            revision = (await resp.Content.ReadFromJsonAsync<SyncUploadResponse>())!.Revision;
        }

        var limited = await client.PutAsJsonAsync("/v1/sync/envelope", new { baseRevision = revision, envelope = Envelope });
        Assert.Equal(HttpStatusCode.TooManyRequests, limited.StatusCode);
        Assert.NotNull(limited.Headers.RetryAfter);
        Assert.Contains("application/problem+json", limited.Content.Headers.ContentType?.MediaType);
        Assert.Equal(HttpStatusCode.TooManyRequests, (await client.DeleteAsync("/v1/sync/envelope")).StatusCode);

        // Reads are not limited by the write bucket.
        Assert.NotEqual(HttpStatusCode.TooManyRequests, (await client.GetAsync("/v1/sync/status")).StatusCode);

        var other = await SignedInAsync();
        Assert.Equal(HttpStatusCode.OK, (await other.PutAsJsonAsync("/v1/sync/envelope", new { baseRevision = 0, envelope = Envelope })).StatusCode);
    }

    [Fact]
    public async Task ALimitedUpload_IsRefusedBeforeTheBodyIsRead()
    {
        var client = await SignedInAsync();
        for (var i = 0; i < 30; i++)
        {
            Assert.Equal(HttpStatusCode.NoContent, (await client.DeleteAsync("/v1/sync/envelope")).StatusCode);
        }

        // A malformed JSON body would be a 400 from model binding if the limiter ran after binding (as an
        // endpoint filter did). Refused by the middleware first, it is a 429 and the body is never parsed.
        using var malformed = new StringContent("{ this is not json", Encoding.UTF8, "application/json");
        var resp = await client.PutAsync("/v1/sync/envelope", malformed);
        Assert.Equal(HttpStatusCode.TooManyRequests, resp.StatusCode);
    }

    [Fact]
    public async Task WithoutASession_TheLimiterNeverRuns_Its401()
    {
        var resp = await _factory.CreateClient().PutAsJsonAsync("/v1/sync/envelope", new { baseRevision = 0, envelope = Envelope });
        Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
    }
}
