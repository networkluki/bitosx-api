using System.Net.Http;
using BitosX.Api.Http;
using Microsoft.AspNetCore.Mvc.Testing;

namespace BitosX.Api.Tests;

public sealed class CorrelationIdTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;

    public CorrelationIdTests(WebApplicationFactory<Program> factory) => _factory = factory;

    [Fact]
    public async Task ServerGeneratesCorrelationId_WhenClientSendsNone()
    {
        var client = _factory.CreateClient();

        var response = await client.GetAsync("/health");

        Assert.True(response.Headers.TryGetValues(CorrelationIdMiddleware.HeaderName, out var values));
        var id = Assert.Single(values!);
        Assert.False(string.IsNullOrWhiteSpace(id));
        Assert.True(id.Length <= 128);
    }

    [Fact]
    public async Task ServerEchoesValidClientCorrelationId()
    {
        const string clientId = "valid-correlation-id-123";
        var client = _factory.CreateClient();

        using var request = new HttpRequestMessage(HttpMethod.Get, "/health");
        request.Headers.TryAddWithoutValidation(CorrelationIdMiddleware.HeaderName, clientId);
        var response = await client.SendAsync(request);

        Assert.True(response.Headers.TryGetValues(CorrelationIdMiddleware.HeaderName, out var values));
        Assert.Equal(clientId, Assert.Single(values!));
    }

    [Fact]
    public async Task ServerReplacesOversizedClientCorrelationId()
    {
        var oversized = new string('a', 200); // exceeds the 128-char bound
        var client = _factory.CreateClient();

        using var request = new HttpRequestMessage(HttpMethod.Get, "/health");
        request.Headers.TryAddWithoutValidation(CorrelationIdMiddleware.HeaderName, oversized);
        var response = await client.SendAsync(request);

        Assert.True(response.Headers.TryGetValues(CorrelationIdMiddleware.HeaderName, out var values));
        var id = Assert.Single(values!);
        Assert.NotEqual(oversized, id);       // not echoed verbatim
        Assert.True(id.Length <= 128);
    }

    [Fact]
    public async Task ServerReplacesCorrelationIdWithControlCharacters()
    {
        // Contains a non-printable control character (0x01) — unsuitable for logs.
        const string malformed = "abcdef";
        var client = _factory.CreateClient();

        using var request = new HttpRequestMessage(HttpMethod.Get, "/health");
        request.Headers.TryAddWithoutValidation(CorrelationIdMiddleware.HeaderName, malformed);
        var response = await client.SendAsync(request);

        Assert.True(response.Headers.TryGetValues(CorrelationIdMiddleware.HeaderName, out var values));
        var id = Assert.Single(values!);
        Assert.NotEqual(malformed, id);       // attacker input never echoed as-is
        Assert.DoesNotContain('', id);
    }
}
