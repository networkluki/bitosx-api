using System.Security.Claims;
using BitosX.Api.Security;
using BitosX.Application.Accounts;
using BitosX.Application.Mfa;
using BitosX.Application.Security;
using BitosX.Application.Sessions;
using BitosX.Application.Verification;
using BitosX.Contracts.Accounts;

namespace BitosX.Api.Endpoints;

/// <summary>
/// Versioned account endpoints (<c>/v1/auth</c>): registration, email verification, password
/// reset. Responses are generic to resist account enumeration; validation errors use RFC7807
/// ProblemDetails. No response exposes password, token, verifier, or account state.
/// </summary>
public static class AuthEndpoints
{
    private const string GenericAccepted =
        "If the address can be registered or needs verification, check your email.";

    private const string EmailUnavailable = "Email verification is temporarily unavailable.";

    private const string GenericResetAccepted =
        "If an account exists for this address, check your email for a password-reset link.";

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

    // Second-step failures (unknown/expired/spent challenge, wrong code, changed password, TOTP disabled meanwhile)
    // all collapse to one generic 401 — never which one, never the attempts left.
    private static IResult InvalidMfa() => Results.Problem(
        statusCode: StatusCodes.Status401Unauthorized, title: "Unauthorized", detail: "Invalid or expired sign-in code.");

    private static IResult SecondFactorUnavailable() => Results.Problem(
        statusCode: StatusCodes.Status503ServiceUnavailable, title: "Service unavailable", detail: "Two-factor sign-in is temporarily unavailable.");

    // Same generic 429 as the limiter filters: never which limiter fired.
    private static IResult TooManyRequests(HttpContext http, TimeSpan? retryAfter)
    {
        var seconds = retryAfter is { } r ? (int)Math.Ceiling(r.TotalSeconds) : 0;
        if (seconds > 0)
        {
            http.Response.Headers.RetryAfter = seconds.ToString(System.Globalization.CultureInfo.InvariantCulture);
        }

        return Results.Problem(statusCode: StatusCodes.Status429TooManyRequests, title: "Too Many Requests", detail: "Too many requests. Try again later.");
    }

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

        group.MapPost("/verify-email", async (VerifyEmailRequest request, HttpContext http, IEmailVerificationService service, CancellationToken ct) =>
        {
            VerifyResult result;
            try
            {
                result = await service.VerifyAsync(new VerifyEmailCommand(request.Token, request.Password), ct);
            }
            catch (PasswordHashingCapacityExceededException)
            {
                return CapacityUnavailable(http); // Argon2 admission overload → 503, the token stays usable
            }

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

        // Forgot-password: queues a reset email for a verified account; the response is identical for an
        // unknown, unverified, disabled or eligible address (anti-enumeration). Email delivery disabled →
        // generic 503 and nothing is created, like register/resend.
        group.MapPost("/forgot-password", async (ForgotPasswordRequest request, AccountCapabilities capabilities, IPasswordResetService service, CancellationToken ct) =>
        {
            if (!capabilities.EmailDeliveryEnabled)
            {
                return EmailDeliveryUnavailable();
            }

            await service.RequestAsync(new ForgotPasswordCommand(request.Email), ct);
            return Results.Json(new AcceptedResponse(GenericResetAccepted), statusCode: StatusCodes.Status202Accepted);
        })
        // Order: per-IP → 4 KiB body → per-normalized-email → service. Inert unless hardening is enabled.
        .AddEndpointFilter(AuthRateLimiting.PasswordResetPerIpFilter)
        .AddEndpointFilter(RejectOversizedBody)
        .AddEndpointFilter(AuthRateLimiting.PasswordResetPerEmailFilter)
        .WithName("ForgotPassword");

        // Reset-password: consumes a reset token, replaces the account password and signs out every
        // session. Stays available without SMTP so an already-issued link can be consumed (like verify-email).
        group.MapPost("/reset-password", async (ResetPasswordRequest request, HttpContext http, IPasswordResetService service, CancellationToken ct) =>
        {
            ResetPasswordResult result;
            try
            {
                result = await service.ResetAsync(new ResetPasswordCommand(request.Token, request.Password), ct);
            }
            catch (PasswordHashingCapacityExceededException)
            {
                return CapacityUnavailable(http); // Argon2 admission overload → 503, the token stays usable
            }

            return result switch
            {
                ResetPasswordResult.Reset => Results.Ok(
                    new AcceptedResponse("Your password has been reset. Sign in again on every device.")),
                ResetPasswordResult.InvalidPassword => Results.Problem(
                    statusCode: StatusCodes.Status400BadRequest, title: "Invalid request",
                    detail: $"Password must be between {AccountPasswordPolicy.MinLength} and {AccountPasswordPolicy.MaxLength} characters."),
                _ => Results.Problem(
                    statusCode: StatusCodes.Status400BadRequest, title: "Invalid request",
                    detail: "Invalid or expired password-reset token."),
            };
        })
        .AddEndpointFilter(AuthRateLimiting.PasswordResetPerIpFilter)
        .AddEndpointFilter(RejectOversizedBody)
        .WithName("ResetPassword");

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

            return result.Outcome switch
            {
                LoginOutcome.Succeeded => Results.Ok(new TokenResponse(
                    result.AccessToken!, result.AccessTokenExpiresAt, result.RefreshToken!, result.RefreshTokenExpiresAt)),
                // Password accepted, second factor required: 202 with the one-step challenge token, no session yet.
                LoginOutcome.MfaRequired => Results.Json(
                    new MfaChallengeResponse(result.MfaToken!, result.MfaTokenExpiresAt), statusCode: StatusCodes.Status202Accepted),
                // TOTP required but the server cannot verify codes: refuse (never a password-only session).
                LoginOutcome.MfaUnavailable => SecondFactorUnavailable(),
                _ => InvalidCredentials(),
            };
        })
        // Order (§2D.2): per-IP → 4 KiB body → per-normalized-email → process-wide budget → credential/Argon2 → jitter.
        .AddEndpointFilter(AuthRateLimiting.LoginPerIpFilter)
        .AddEndpointFilter(RejectOversizedBody)
        .AddEndpointFilter(AuthRateLimiting.LoginPerEmailFilter)
        .AddEndpointFilter(AuthRateLimiting.GlobalLoginBudgetFilter)
        .WithName("Login");

        // Second sign-in step: UNAUTHENTICATED (there is no session yet); identity comes from the opaque
        // challenge token issued by the password step, never from the body. No Argon2 runs here.
        group.MapPost("/login/totp", async (TotpLoginRequest request, HttpContext http, AccountCapabilities capabilities, ILoginResponseJitter jitter, CancellationToken ct) =>
        {
            if (!capabilities.TotpEnabled)
            {
                return SecondFactorUnavailable();
            }

            var service = http.RequestServices.GetRequiredService<IMfaLoginService>();
            var result = await service.CompleteAsync(new MfaLoginCommand(request.MfaToken, request.Code), ct);

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

            return result.Outcome switch
            {
                LoginOutcome.Succeeded => Results.Ok(new TokenResponse(
                    result.AccessToken!, result.AccessTokenExpiresAt, result.RefreshToken!, result.RefreshTokenExpiresAt)),
                // Per-account budget (MfaPerAccount) used up, or its limiter at capacity: the generic limiter contracts.
                LoginOutcome.RateLimited => TooManyRequests(http, result.RetryAfter),
                LoginOutcome.TemporarilyUnavailable => Results.Problem(
                    statusCode: StatusCodes.Status503ServiceUnavailable, title: "Service unavailable", detail: "Service temporarily unavailable."),
                _ => InvalidMfa(),
            };
        })
        // Order: per-IP → 4 KiB body → service (per-account limit once the challenge names the account).
        .AddEndpointFilter(AuthRateLimiting.MfaPerIpFilter)
        .AddEndpointFilter(RejectOversizedBody)
        .WithName("LoginTotp");

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
