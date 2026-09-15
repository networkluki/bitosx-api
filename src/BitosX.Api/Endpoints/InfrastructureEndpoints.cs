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
    public static IEndpointRouteBuilder MapInfrastructureEndpoints(this IEndpointRouteBuilder app)
    {
        // Liveness only. There is no database in this milestone, so this does
        // not — and must not — claim database or dependency readiness.
        app.MapGet("/health", () => new HealthResponse(ServiceInfo.Name, "healthy"))
            .WithName("Health")
            .WithTags("Infrastructure");

        // Non-sensitive product/build version, read from assembly metadata.
        app.MapGet("/version", (IProductVersionProvider versions) =>
                new VersionResponse(ServiceInfo.Name, versions.GetProductVersion()))
            .WithName("Version")
            .WithTags("Infrastructure");

        return app;
    }
}
