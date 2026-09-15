namespace BitosX.Api.Endpoints;

/// <summary>
/// Routing seam for future versioned business endpoints. All business APIs
/// (e.g. <c>/v1/auth/...</c>, <c>/v1/account/...</c>) will hang off this group.
///
/// Intentionally empty in the API-foundation milestone: no auth, account,
/// sync, or vault endpoints exist yet.
/// </summary>
public static class ApiV1Endpoints
{
    public static RouteGroupBuilder MapApiV1(this IEndpointRouteBuilder app)
        => app.MapGroup("/v1");
}
