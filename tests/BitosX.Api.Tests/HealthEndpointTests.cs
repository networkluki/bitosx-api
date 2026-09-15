using System.Net;
using System.Net.Http.Json;
using BitosX.Contracts.Health;
using Microsoft.AspNetCore.Mvc.Testing;

namespace BitosX.Api.Tests;

public sealed class HealthEndpointTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;

    public HealthEndpointTests(WebApplicationFactory<Program> factory) => _factory = factory;

    [Fact]
    public async Task Get_Health_ReturnsHealthyLiveness()
    {
        var client = _factory.CreateClient();

        var response = await client.GetAsync("/health");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var body = await response.Content.ReadFromJsonAsync<HealthResponse>();

        Assert.NotNull(body);
        Assert.Equal("BitosX API", body!.Service);
        Assert.Equal("healthy", body.Status);
    }
}
