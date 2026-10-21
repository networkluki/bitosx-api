using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using BitosX.Contracts.Sync;

namespace BitosX.Api.Tests;

/// <summary>
/// The sync endpoints end to end (register → verify → login → sync) against bitosx_test: the
/// compare-and-set contract over HTTP, the shape and size refusals, isolation between accounts, and
/// that nothing is reachable without a session.
/// </summary>
public sealed class SyncEndpointTests : IClassFixture<LoginApiFactory>, IAsyncLifetime
{
    private const string Password = "Correct-Horse-Battery-Staple-1";
    private const string Envelope = "{\"version\":1,\"kdf\":\"argon2id\",\"ciphertext\":\"AAAA\"}";

    private readonly LoginApiFactory _factory;

    public SyncEndpointTests(LoginApiFactory factory) => _factory = factory;

    public async Task InitializeAsync() => await _factory.ResetDatabaseAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    private async Task<HttpClient> SignedInClientAsync()
    {
        var client = _factory.CreateClient();
        var email = await _factory.CreateVerifiedAccountAsync(client, Password);
        var tokens = await LoginApiFactory.LoginAsync(client, email, Password);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tokens.AccessToken);
        return client;
    }

    private static string B64(string text) => Convert.ToBase64String(Encoding.UTF8.GetBytes(text));

    private static string Fingerprint(string text) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(text)));

    [Fact]
    public async Task WithoutASession_EverySyncEndpointIs401()
    {
        var client = _factory.CreateClient();

        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/v1/sync/status")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/v1/sync/envelope")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.PutAsJsonAsync("/v1/sync/envelope", new { baseRevision = 0, envelope = B64(Envelope) })).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.DeleteAsync("/v1/sync/envelope")).StatusCode);
    }

    [Fact]
    public async Task NothingStored_Is404_OnStatusAndDownload()
    {
        var client = await SignedInClientAsync();

        Assert.Equal(HttpStatusCode.NotFound, (await client.GetAsync("/v1/sync/status")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await client.GetAsync("/v1/sync/envelope")).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await client.DeleteAsync("/v1/sync/envelope")).StatusCode);
    }

    [Fact]
    public async Task Upload_ThenStatusAndDownload_RoundTrip()
    {
        var client = await SignedInClientAsync();

        var put = await client.PutAsJsonAsync("/v1/sync/envelope", new { baseRevision = 0, envelope = B64(Envelope) });
        Assert.Equal(HttpStatusCode.OK, put.StatusCode);
        var stored = await put.Content.ReadFromJsonAsync<SyncUploadResponse>();
        Assert.Equal(1, stored!.Revision);
        Assert.Equal(Fingerprint(Envelope), stored.Fingerprint);
        Assert.Equal(Encoding.UTF8.GetByteCount(Envelope), stored.SizeBytes);

        var status = await (await client.GetAsync("/v1/sync/status")).Content.ReadFromJsonAsync<SyncStatusResponse>();
        Assert.Equal(1, status!.Revision);
        Assert.Equal(Fingerprint(Envelope), status.Fingerprint);

        var download = await client.GetAsync("/v1/sync/envelope");
        Assert.Equal(HttpStatusCode.OK, download.StatusCode);
        Assert.Equal("no-store", download.Headers.CacheControl?.ToString());
        var body = await download.Content.ReadFromJsonAsync<SyncEnvelopeResponse>();
        Assert.Equal(Envelope, Encoding.UTF8.GetString(Convert.FromBase64String(body!.Envelope)));
        Assert.Equal(1, body.Revision);
    }

    [Fact]
    public async Task Upload_AgainstAStaleRevision_Is409_WithTheCurrentRevision_AndNothingChanges()
    {
        var client = await SignedInClientAsync();
        await client.PutAsJsonAsync("/v1/sync/envelope", new { baseRevision = 0, envelope = B64(Envelope) });
        await client.PutAsJsonAsync("/v1/sync/envelope", new { baseRevision = 1, envelope = B64(Envelope + " ") });

        var stale = await client.PutAsJsonAsync("/v1/sync/envelope", new { baseRevision = 1, envelope = B64("{\"version\":1,\"ciphertext\":\"ZZZZ\"}") });

        Assert.Equal(HttpStatusCode.Conflict, stale.StatusCode);
        Assert.Equal("application/problem+json", stale.Content.Headers.ContentType?.MediaType);
        using var problem = JsonDocument.Parse(await stale.Content.ReadAsStringAsync());
        Assert.Equal(2, problem.RootElement.GetProperty("currentRevision").GetInt64());
        var status = await (await client.GetAsync("/v1/sync/status")).Content.ReadFromJsonAsync<SyncStatusResponse>();
        Assert.Equal(2, status!.Revision);
        Assert.Equal(Fingerprint(Envelope + " "), status.Fingerprint);
    }

    [Theory]
    [InlineData("not base64 at all!")]
    [InlineData("")]
    public async Task Upload_OfSomethingThatIsNotBase64_Is400(string envelope)
    {
        var client = await SignedInClientAsync();
        var resp = await client.PutAsJsonAsync("/v1/sync/envelope", new { baseRevision = 0, envelope });
        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
    }

    [Theory]
    [InlineData("just text")]
    [InlineData("[1]")]
    [InlineData("{\"noVersion\":true}")]
    public async Task Upload_OfSomethingThatIsNotAnEnvelope_Is400_AndStoresNothing(string text)
    {
        var client = await SignedInClientAsync();

        var resp = await client.PutAsJsonAsync("/v1/sync/envelope", new { baseRevision = 0, envelope = B64(text) });

        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await client.GetAsync("/v1/sync/status")).StatusCode);
    }

    [Fact]
    public async Task Upload_WithANegativeBaseRevision_Is400()
    {
        var client = await SignedInClientAsync();
        var resp = await client.PutAsJsonAsync("/v1/sync/envelope", new { baseRevision = -1, envelope = B64(Envelope) });
        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
    }

    [Fact]
    public async Task Upload_LargerThanKestrelsDefault_ButWithinTheSyncLimit_Succeeds()
    {
        // 200 KiB: more than the 64 KB Kestrel default every other endpoint keeps.
        var client = await SignedInClientAsync();
        var big = "{\"version\":1,\"ciphertext\":\"" + new string('A', 200 * 1024) + "\"}";

        var resp = await client.PutAsJsonAsync("/v1/sync/envelope", new { baseRevision = 0, envelope = B64(big) });

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var download = await (await client.GetAsync("/v1/sync/envelope")).Content.ReadFromJsonAsync<SyncEnvelopeResponse>();
        Assert.Equal(big, Encoding.UTF8.GetString(Convert.FromBase64String(download!.Envelope)));
    }

    [Fact]
    public async Task TwoAccounts_NeverSeeEachOthersEnvelope()
    {
        var alice = await SignedInClientAsync();
        var bob = await SignedInClientAsync();
        await alice.PutAsJsonAsync("/v1/sync/envelope", new { baseRevision = 0, envelope = B64(Envelope) });

        Assert.Equal(HttpStatusCode.NotFound, (await bob.GetAsync("/v1/sync/status")).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await bob.DeleteAsync("/v1/sync/envelope")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await alice.GetAsync("/v1/sync/status")).StatusCode);
    }

    [Fact]
    public async Task Delete_RemovesTheEnvelope_AndTheNextUploadStartsOver()
    {
        var client = await SignedInClientAsync();
        await client.PutAsJsonAsync("/v1/sync/envelope", new { baseRevision = 0, envelope = B64(Envelope) });

        Assert.Equal(HttpStatusCode.NoContent, (await client.DeleteAsync("/v1/sync/envelope")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await client.GetAsync("/v1/sync/status")).StatusCode);

        var again = await client.PutAsJsonAsync("/v1/sync/envelope", new { baseRevision = 0, envelope = B64(Envelope) });
        Assert.Equal(1, (await again.Content.ReadFromJsonAsync<SyncUploadResponse>())!.Revision);
    }

    [Fact]
    public async Task AfterLogout_TheSyncEndpointsAre401()
    {
        var client = await SignedInClientAsync();
        await client.PutAsJsonAsync("/v1/sync/envelope", new { baseRevision = 0, envelope = B64(Envelope) });
        Assert.Equal(HttpStatusCode.NoContent, (await client.PostAsync("/v1/auth/logout", null)).StatusCode);

        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/v1/sync/envelope")).StatusCode);
    }
}
