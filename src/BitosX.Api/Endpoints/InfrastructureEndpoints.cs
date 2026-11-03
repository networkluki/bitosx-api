using BitosX.Application;
using BitosX.Application.Versioning;
using BitosX.Contracts.Health;
using BitosX.Contracts.Version;

namespace BitosX.Api.Endpoints;

/// <summary>
/// Unversioned infrastructure endpoints (liveness / build info). These are
/// intentionally outside the future <c>/v1</c> business-API surface.
/// </summary>
public static class InfrastructureEndpoints
{
    /// <param name="app">The route builder.</param>
    /// <param name="corsPolicyName">
    /// The CORS policy for these two endpoints (the narrow status policy that also admits the product page),
    /// or null when no CORS policy is configured.
    /// </param>
    public static IEndpointRouteBuilder MapInfrastructureEndpoints(this IEndpointRouteBuilder app, string? corsPolicyName = null)
    {
        // Process liveness only: it does not — and must not — claim database or dependency readiness, so a
        // public probe learns nothing about the configuration behind it.
        var health = app.MapGet("/health", () => new HealthResponse(ServiceInfo.Name, "healthy"))
            .WithName("Health")
            .WithTags("Infrastructure");

        // Non-sensitive product/build version, read from assembly metadata.
        var version = app.MapGet("/version", (IProductVersionProvider versions) =>
                new VersionResponse(ServiceInfo.Name, versions.GetProductVersion()))
            .WithName("Version")
            .WithTags("Infrastructure");

        if (corsPolicyName is not null)
        {
            health.RequireCors(corsPolicyName);
            version.RequireCors(corsPolicyName);
        }

        return app;
    }
}
