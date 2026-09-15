using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using BitosX.Contracts.Version;
using Microsoft.AspNetCore.Mvc.Testing;

namespace BitosX.Api.Tests;

public sealed class VersionEndpointTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;

    public VersionEndpointTests(WebApplicationFactory<Program> factory) => _factory = factory;

    [Fact]
    public async Task Get_Version_ReturnsServiceAndVersion()
    {
        var client = _factory.CreateClient();

        var response = await client.GetAsync("/version");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var body = await response.Content.ReadFromJsonAsync<VersionResponse>();

        Assert.NotNull(body);
        Assert.Equal("BitosX API", body!.Service);
        Assert.False(string.IsNullOrWhiteSpace(body.Version));
        // Non-sensitive, clean semantic version: no build metadata, no paths.
        Assert.Matches(@"^\d+\.\d+\.\d+", body.Version);
        Assert.DoesNotContain('+', body.Version);
        Assert.DoesNotContain('/', body.Version);
        Assert.DoesNotContain('\\', body.Version);
    }

    [Fact]
    public async Task Get_Version_ExposesOnlyServiceAndVersionFields()
    {
        var client = _factory.CreateClient();

        var json = await client.GetStringAsync("/version");
        using var doc = JsonDocument.Parse(json);

        var propertyNames = doc.RootElement.EnumerateObject()
            .Select(p => p.Name)
            .OrderBy(n => n, StringComparer.Ordinal)
            .ToArray();

        // Guards the zero-knowledge boundary: the response must not grow extra
        // fields that could leak host/build/environment details.
        Assert.Equal(new[] { "service", "version" }, propertyNames);
    }
}
