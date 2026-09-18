using System.Security.Claims;
using BitosX.Api.Security;
using BitosX.Application.Accounts;
using BitosX.Application.Security;
using BitosX.Application.Sessions;
using BitosX.Application.Verification;
using BitosX.Contracts.Accounts;

namespace BitosX.Api.Endpoints;

/// <summary>
/// Versioned account endpoints (<c>/v1/auth</c>). Responses are generic to resist
/// account enumeration; validation errors use RFC7807 ProblemDetails. No response
/// exposes password, token, verifier, or account state.
/// </summary>
public static class AuthEndpoints
{
    private const string GenericAccepted =
        "If the address can be registered or needs verification, check your email.";

    private const string EmailUnavailable = "Email verification is temporarily unavailable.";

    /// <summary>Per-endpoint request-body cap for auth endpoints (§5.4), tighter than the global 64 KiB.</summary>
    private const long MaxAuthBodyBytes = 4 * 1024;

    private const int UserAgentMaxLength = 255; // matches sessions.user_agent VARCHAR(255)

    private static IResult EmailDeliveryUnavailable() => Results.Problem(
        statusCode: StatusCodes.Status503ServiceUnavailable, title: "Service unavailable", detail: EmailUnavailable);

    // Single generic credential failure — no distinction between unknown/bad-password/unverified/
    // disabled/null-hash/invalid-format, and no account-existence signal (anti-enumeration, §11.1).
    private static IResult InvalidCredentials() => Results.Problem(
        statusCode: StatusCodes.Status401Unauthorized, title: "Unauthorized", detail: "Invalid email or password.");

    // Single generic refresh failure — unknown/malformed/expired/revoked/reused all collapse here so
    // the response never discloses which token/session state was hit (anti-enumeration, §11.1).
    private static IResult InvalidRefresh() => Results.Problem(
        statusCode: StatusCodes.Status401Unauthorized, title: "Unauthorized", detail: "Invalid or expired refresh token.");

    private static IResult Unauthenticated() => Results.Problem(
        statusCode: StatusCodes.Status401Unauthorized, title: "Unauthorized", detail: "Authentication required.");

    // Authoritative identity from the validated JWT claims (raw sub/sid; MapInboundClaims=false).
    // NEVER trust account/session ids from the request body. The SessionValidation seam has already
    // proven these are well-formed and the session is active by the time an authenticated handler runs.
    private static bool TryGetAuthenticatedIds(ClaimsPrincipal user, out Guid accountId, out Guid sessionId)
    {
        sessionId = Guid.Empty;
        return Guid.TryParse(user.FindFirst("sub")?.Value, out accountId)
            && Guid.TryParse(user.FindFirst("sid")?.Value, out sessionId)
            && accountId != Guid.Empty
            && sessionId != Guid.Empty;
    }

    private static IResult PayloadTooLarge() => Results.Problem(
        statusCode: StatusCodes.Status413PayloadTooLarge, title: "Payload too large", detail: "Request body exceeds the allowed size.");

    // Argon2 admission overload (queue full or acquire timeout) and unexpected post-credential jitter
    // failure both fail closed as a generic 503 with Retry-After: 1 — never 401, never any account/queue detail.
    private static IResult CapacityUnavailable(HttpContext http)
    {
        http.Response.Headers.RetryAfter = "1";
        return Results.Problem(
            statusCode: StatusCodes.Status503ServiceUnavailable,
            title: "Service unavailable",
            detail: "Service temporarily unavailable. Try again later.");
    }

    // Rejects an oversized body BEFORE the handler evaluates credentials. Minimal-API filters run after
    // model binding, so a malformed body still yields the framework's 400; an over-limit body with a
    // known Content-Length is short-circuited to 413 here (the global 64 KiB Kestrel cap bounds the rest).
    private static async ValueTask<object?> RejectOversizedBody(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
        => context.HttpContext.Request.ContentLength is > MaxAuthBodyBytes ? PayloadTooLarge() : await next(context);

    private static string? TrimUserAgent(string? userAgent)
        => string.IsNullOrWhiteSpace(userAgent) ? null
            : (userAgent.Length > UserAgentMaxLength ? userAgent[..UserAgentMaxLength] : userAgent);

    public static IEndpointRouteBuilder MapAuthEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/v1/auth").WithTags("Auth");

        group.MapPost("/register", async (RegisterRequest request, AccountCapabilities capabilities, IAccountRegistrationService service, CancellationToken ct) =>
        {
            // Email delivery unavailable: generic 503, and DO NOT enqueue undeliverable mail
            // (the registration service is not invoked, so no account/challenge/outbox is created).
            if (!capabilities.EmailDeliveryEnabled)
            {
                return EmailDeliveryUnavailable();
            }

            var result = await service.RegisterAsync(new RegisterCommand(request.Email), ct);
            return result == RegistrationResult.InvalidEmail
                ? Results.Problem(statusCode: StatusCodes.Status400BadRequest, title: "Invalid request",
                    detail: "A valid email address is required.")
                : Results.Json(new AcceptedResponse(GenericAccepted), statusCode: StatusCodes.Status202Accepted);
        }).WithName("Register");

        group.MapPost("/verify-email", async (VerifyEmailRequest request, IEmailVerificationService service, CancellationToken ct) =>
        {
            var result = await service.VerifyAsync(new VerifyEmailCommand(request.Token, request.Password), ct);
            return result switch
            {
                VerifyResult.Verified => Results.Ok(
                    new AcceptedResponse("Your email is verified and your password is set.")),
                VerifyResult.InvalidPassword => Results.Problem(
                    statusCode: StatusCodes.Status400BadRequest, title: "Invalid request",
                    detail: $"Password must be between {AccountPasswordPolicy.MinLength} and {AccountPasswordPolicy.MaxLength} characters."),
                _ => Results.Problem(
                    statusCode: StatusCodes.Status400BadRequest, title: "Invalid request",
                    detail: "Invalid or expired verification token."),
            };
        }).WithName("VerifyEmail");

        group.MapPost("/resend-verification", async (ResendVerificationRequest request, AccountCapabilities capabilities, IEmailVerificationService service, CancellationToken ct) =>
        {
            if (!capabilities.EmailDeliveryEnabled)
            {
                return EmailDeliveryUnavailable();
            }

            await service.ResendAsync(new ResendCommand(request.Email), ct);
            return Results.Json(new AcceptedResponse(GenericAccepted), statusCode: StatusCodes.Status202Accepted);
        }).WithName("ResendVerification");

        return app;
    }

    /// <summary>
    /// Login endpoint (<c>/v1/auth</c>), mapped only when the Login capability is enabled. The
    /// account password is passed to the service exactly as supplied (bounds are enforced inside the
    /// service before Argon2/DB, so an oversized/invalid credential collapses to the same generic 401
    /// with no hashing). The session's client descriptor comes from the User-Agent header, never the body.
    /// </summary>
    public static IEndpointRouteBuilder MapLoginEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/v1/auth").WithTags("Auth");

        group.MapPost("/login", async (LoginRequest request, HttpContext http, ILoginService service, ILoginResponseJitter jitter, CancellationToken ct) =>
        {
            LoginResult result;
            try
            {
                var userAgent = TrimUserAgent(http.Request.Headers.UserAgent.ToString());
                result = await service.LoginAsync(new LoginCommand(request.Email, request.Password, userAgent), ct);
            }
            catch (PasswordHashingCapacityExceededException)
            {
                return CapacityUnavailable(http); // Argon2 admission overload → 503 (never a credential 401)
            }

            // Defense-in-depth jitter applies ONLY to the normal credential outcomes (200 / generic 401),
            // after credential evaluation. Genuine cancellation stays cancellation; an unexpected jitter
            // failure fails closed.
            try
            {
                await jitter.ApplyAsync(ct);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch
            {
                return CapacityUnavailable(http);
            }

            return result.Outcome == LoginOutcome.Succeeded
                ? Results.Ok(new TokenResponse(
                    result.AccessToken!, result.AccessTokenExpiresAt, result.RefreshToken!, result.RefreshTokenExpiresAt))
                : InvalidCredentials();
        })
        // Order (§2D.2): per-IP → 4 KiB body → per-normalized-email → process-wide budget → credential/Argon2 → jitter.
        .AddEndpointFilter(AuthRateLimiting.LoginPerIpFilter)
        .AddEndpointFilter(RejectOversizedBody)
        .AddEndpointFilter(AuthRateLimiting.LoginPerEmailFilter)
        .AddEndpointFilter(AuthRateLimiting.GlobalLoginBudgetFilter)
        .WithName("Login");

        // Refresh is UNAUTHENTICATED: the access token may already be expired. Identity is resolved
        // from the opaque refresh token by the store (strict reuse handled there), never from claims.
        group.MapPost("/refresh", async (RefreshRequest request, IRefreshService service, CancellationToken ct) =>
        {
            var result = await service.RefreshAsync(new RefreshCommand(request.RefreshToken), ct);

            return result.Outcome == RefreshOutcome.Succeeded
                ? Results.Ok(new TokenResponse(
                    result.AccessToken!, result.AccessTokenExpiresAt, result.RefreshToken!, result.RefreshTokenExpiresAt))
                : InvalidRefresh();
        })
        .AddEndpointFilter(AuthRateLimiting.RefreshPerIpFilter)
        .AddEndpointFilter(RejectOversizedBody)
        .WithName("Refresh");

        // Logout / logout-all are AUTHENTICATED: identity comes from the validated JWT, never the body.
        group.MapPost("/logout", async (HttpContext http, ISessionManagementService service, CancellationToken ct) =>
        {
            if (!TryGetAuthenticatedIds(http.User, out var accountId, out var sessionId))
            {
                return Unauthenticated();
            }

            await service.LogoutAsync(accountId, sessionId, ct); // revokes only the caller's current session
            return Results.NoContent();
        })
        .RequireAuthorization()
        .WithName("Logout");

        group.MapPost("/logout-all", async (HttpContext http, ISessionManagementService service, CancellationToken ct) =>
        {
            if (!TryGetAuthenticatedIds(http.User, out var accountId, out _))
            {
                return Unauthenticated();
            }

            await service.LogoutAllAsync(accountId, ct); // revokes every session for the account
            return Results.NoContent();
        })
        .RequireAuthorization()
        .WithName("LogoutAll");

        return app;
    }
}
