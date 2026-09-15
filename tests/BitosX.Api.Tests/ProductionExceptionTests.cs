using System.Net;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;

namespace BitosX.Api.Tests;

/// <summary>
/// Proves the production error pipeline: unhandled exceptions become RFC7807
/// ProblemDetails with no leakage of exception type, message, path, or stack.
///
/// The exception is triggered by a TEST-ONLY endpoint injected via the DI
/// endpoint-contribution seam. There is no throw endpoint in production.
/// </summary>
public sealed class ProductionExceptionTests
{
    // Distinctive tokens that must never appear in the client-facing response.
    private const string SecretMessage = "SENSITIVE_EXCEPTION_MESSAGE_do_not_leak";
    private const string SecretPath = "/srv/bitosx/secret-source.cs";

    private static WebApplicationFactory<Program> CreateProductionFactory()
        => new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
        {
            builder.UseEnvironment("Production");
            builder.ConfigureTestServices(services =>
            {
                services.AddSingleton<Action<IEndpointRouteBuilder>>(endpoints =>
                    endpoints.MapGet("/__test/throw", (Action)(() =>
                        throw new InvalidOperationException($"{SecretMessage} at {SecretPath}:42"))));
            });
        });

    [Fact]
    public async Task UnhandledException_ReturnsProblemDetails_WithoutLeakingDetails()
    {
        using var factory = CreateProductionFactory();
        var client = factory.CreateClient();

        var response = await client.GetAsync("/__test/throw");
        var body = await response.Content.ReadAsStringAsync();

        // 500 + RFC7807 content type.
        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
        Assert.NotNull(response.Content.Headers.ContentType);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType!.MediaType);

        // No internal detail leakage of any kind.
        Assert.DoesNotContain(SecretMessage, body);
        Assert.DoesNotContain(SecretPath, body);
        Assert.DoesNotContain("InvalidOperationException", body);
        Assert.DoesNotContain(".cs", body);
        Assert.DoesNotContain(" at ", body);          // stack-frame marker
        Assert.DoesNotContain("StackTrace", body);
        Assert.DoesNotContain("System.", body);        // no CLR type leakage
    }
}
