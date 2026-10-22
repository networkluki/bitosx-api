using System.Security.Claims;
using BitosX.Api.Security;
using BitosX.Application.Abstractions.Persistence;
using BitosX.Application.Accounts;
using BitosX.Application.Security;
using BitosX.Application.Sessions;
using BitosX.Contracts.Accounts;

namespace BitosX.Api.Endpoints;

/// <summary>
/// Protected account endpoints (<c>/v1/account</c>), mapped only when the Login capability is enabled
/// and requiring authentication. Every handler is composition/translation only: identity comes from the
/// validated JWT claims (the SessionValidation seam has already proven the session is active), ownership
/// and effective-expiry/revocation rules live entirely in the Application session services, and DTOs are
/// mapped explicitly so no persistence/domain field leaks into the HTTP contract.
/// </summary>
public static class AccountEndpoints
{
    private static IResult Unauthenticated() => Results.Problem(
        statusCode: StatusCodes.Status401Unauthorized, title: "Unauthorized", detail: "Authentication required.");

    /// <summary>Per-endpoint request-body cap for the password-confirmed delete (same as the auth endpoints).</summary>
    private const long MaxBodyBytes = 4 * 1024;

    // One generic confirmation failure: wrong password and an account that cannot be deleted this way are
    // indistinguishable. 403 (not 401) so a client does not mistake it for a dead session and sign out.
    private static IResult PasswordConfirmationFailed() => Results.Problem(
        statusCode: StatusCodes.Status403Forbidden, title: "Forbidden", detail: "Password confirmation failed.");

    private static IResult PayloadTooLarge() => Results.Problem(
        statusCode: StatusCodes.Status413PayloadTooLarge, title: "Payload too large", detail: "Request body exceeds the allowed size.");

    private static IResult CapacityUnavailable(HttpContext http)
    {
        http.Response.Headers.RetryAfter = "1";
        return Results.Problem(
            statusCode: StatusCodes.Status503ServiceUnavailable, title: "Service unavailable",
            detail: "Service temporarily unavailable. Try again later.");
    }

    private static async ValueTask<object?> RejectOversizedBody(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
        => context.HttpContext.Request.ContentLength is > MaxBodyBytes ? PayloadTooLarge() : await next(context);

    // Identical 404 for a nonexistent AND a non-owned session — never discloses existence/ownership.
    private static IResult SessionNotFound() => Results.Problem(
        statusCode: StatusCodes.Status404NotFound, title: "Not found", detail: "Session not found.");

    // Authoritative identity from the validated JWT claims (raw sub/sid; MapInboundClaims=false).
    // NEVER trust account/session ids from the route or body.
    private static bool TryGetAuthenticatedIds(ClaimsPrincipal user, out Guid accountId, out Guid sessionId)
    {
        sessionId = Guid.Empty;
        return Guid.TryParse(user.FindFirst("sub")?.Value, out accountId)
            && Guid.TryParse(user.FindFirst("sid")?.Value, out sessionId)
            && accountId != Guid.Empty
            && sessionId != Guid.Empty;
    }

    public static IEndpointRouteBuilder MapAccountEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/v1/account").WithTags("Account").RequireAuthorization();

        group.MapGet("/me", async (HttpContext http, IAccountRepository accounts, CancellationToken ct) =>
        {
            if (!TryGetAuthenticatedIds(http.User, out var accountId, out _))
            {
                return Unauthenticated();
            }

            var account = await accounts.GetByIdAsync(accountId, ct);
            if (account is null)
            {
                return Unauthenticated(); // fail closed: a valid session with no account is not a leak vector
            }

            return Results.Ok(new MeResponse(account.Id, account.Email, account.EmailVerifiedAt is not null, account.CreatedAt));
        }).WithName("Me");

        group.MapGet("/sessions", async (HttpContext http, ISessionManagementService sessions, CancellationToken ct) =>
        {
            if (!TryGetAuthenticatedIds(http.User, out var accountId, out var sessionId))
            {
                return Unauthenticated();
            }

            // The service returns only the caller's current-usable sessions with the effective expiry and
            // current-session flag already computed — the endpoint recomputes none of that.
            var items = await sessions.ListSessionsAsync(accountId, sessionId, ct);
            var response = items
                .Select(s => new SessionResponse(s.Id, s.CreatedAt, s.LastSeenAt, s.ExpiresAt, s.Current))
                .ToList();
            return Results.Ok(response);
        }).WithName("Sessions");

        // {id:guid} route constraint: a non-GUID id does not match this route (→ 404), so a malformed id
        // never reaches the service as a valid target.
        group.MapDelete("/sessions/{id:guid}", async (Guid id, HttpContext http, ISessionManagementService sessions, CancellationToken ct) =>
        {
            if (!TryGetAuthenticatedIds(http.User, out var accountId, out var sessionId))
            {
                return Unauthenticated();
            }

            // Ownership is enforced server-side by the account id; NotFound covers both a nonexistent and a
            // non-owned session. Deleting the caller's current session is allowed (effectively logout).
            var result = await sessions.DeleteSessionAsync(accountId, sessionId, id, ct);
            return result == DeleteSessionResult.Succeeded ? Results.NoContent() : SessionNotFound();
        }).WithName("DeleteSession");

        // Permanent deletion of the caller's own account, confirmed with the account password. Removes the
        // account and, by cascade, its sessions, refresh tokens, challenges, queued mail and the stored
        // vault envelope. The password is verified with Argon2 outside any lock and re-checked (as the exact
        // hash) under the account lock by the store. POST (not DELETE) because the confirmation is a body.
        group.MapPost("/delete", async (DeleteAccountRequest request, HttpContext http, IAccountDeletionService service, CancellationToken ct) =>
        {
            if (!TryGetAuthenticatedIds(http.User, out var accountId, out _))
            {
                return Unauthenticated();
            }

            DeleteAccountResult result;
            try
            {
                result = await service.DeleteAsync(new DeleteAccountCommand(accountId, request.Password), ct);
            }
            catch (PasswordHashingCapacityExceededException)
            {
                return CapacityUnavailable(http);
            }

            return result == DeleteAccountResult.Deleted ? Results.NoContent() : PasswordConfirmationFailed();
        })
        .AddEndpointFilter(AuthRateLimiting.AccountDeletePerAccountFilter)
        .AddEndpointFilter(RejectOversizedBody)
        .WithName("DeleteAccount");

        return app;
    }
}
