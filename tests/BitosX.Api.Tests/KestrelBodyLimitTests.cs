using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;

namespace BitosX.Api.Tests;

/// <summary>
/// The 64 KB request-body cap is a KESTREL limit, which TestServer does not enforce, so these run the API on a
/// real Kestrel listener (loopback, dynamic port): every other endpoint keeps the 64 KB cap, and only the
/// envelope upload is raised (by MaxRequestBodySizeMiddleware, from VaultSyncOptions).
/// </summary>
public sealed class KestrelBodyLimitTests
{
    private const string Password = "Correct-Horse-Battery-Staple-1";

    private static LoginApiFactory KestrelFactory()
    {
        var factory = new LoginApiFactory { KestrelListenerUrl = "http://127.0.0.1:0" };
        factory.UseKestrel(0);
        return factory;
    }

    [Fact]
    public async Task OnKestrel_AnOrdinaryEndpointRefusesABodyOver64KB_TheEnvelopeUploadAcceptsMore()
    {
        await using var factory = KestrelFactory();
        var client = factory.CreateClient();

        // register has no endpoint-level size filter: only Kestrel's 64 KB cap stands between it and a big body.
        var huge = "{\"email\":\"x@example.com\",\"padding\":\"" + new string('a', 100 * 1024) + "\"}";
        var refused = await client.PostAsync("/v1/auth/register", new StringContent(huge, Encoding.UTF8, "application/json"));
        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, refused.StatusCode);

        var email = await factory.CreateVerifiedAccountAsync(client, Password);
        var tokens = await LoginApiFactory.LoginAsync(client, email, Password);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tokens.AccessToken);

        var big = "{\"version\":1,\"ciphertext\":\"" + new string('A', 200 * 1024) + "\"}";
        var upload = await client.PutAsJsonAsync("/v1/sync/envelope", new { baseRevision = 0, envelope = Convert.ToBase64String(Encoding.UTF8.GetBytes(big)) });
        Assert.Equal(HttpStatusCode.OK, upload.StatusCode);
    }
}
