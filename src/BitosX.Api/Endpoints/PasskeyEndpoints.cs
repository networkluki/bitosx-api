using System.Security.Claims;
using System.Text.Json;
using BitosX.Api.Security;
using BitosX.Application.Passkeys;
using BitosX.Application.Security;
using BitosX.Application.Sessions;
using BitosX.Contracts.Accounts;

namespace BitosX.Api.Endpoints;

/// <summary>
/// Passkeys (WebAuthn), mapped only with the Passkeys capability (otherwise every route is 404): management of the
/// signed-in account's passkeys under <c>/v1/account/passkeys</c>, the passkey second sign-in step under
/// <c>/v1/auth/login/passkey</c>, and sign-in without email and password under <c>/v1/auth/passkey</c>. Options
/// and credentials are the standard WebAuthn JSON. Every sign-in failure is one generic 401; every confirmation
/// failure one generic 403. Identity comes from the validated JWT or from the server-side ceremony, never the body.
/// </summary>
public static class PasskeyEndpoints
{
    /// <summary>Bodies without a credential (password + code, a name, a token).</summary>
    private const long MaxSmallBodyBytes = 4 * 1024;

    /// <summary>Bodies with a WebAuthn credential: an attestation object may carry a certificate chain even with conveyance "none".</summary>
    private const long MaxCredentialBodyBytes = 16 * 1024;

    private const int UserAgentMaxLength = 255; // sessions.user_agent

    private static IResult Unauthenticated() => Results.Problem(
        statusCode: StatusCodes.Status401Unauthorized, title: "Unauthorized", detail: "Authentication required.");

    private static IResult ConfirmationFailed() => Results.Problem(
        statusCode: StatusCodes.Status403Forbidden, title: "Forbidden", detail: "Password confirmation failed.");

    private static IResult TwoFactorRequired() => Results.Problem(
        statusCode: StatusCodes.Status409Conflict, title: "Conflict", detail: "Two-factor authentication is required before a passkey can be added.");

    private static IResult LimitReached() => Results.Problem(
        statusCode: StatusCodes.Status409Conflict, title: "Conflict", detail: $"An account can have at most {WebAuthnOptions.MaxPasskeysPerAccount} passkeys. Remove one first.");

    private static IResult InvalidName() => Results.Problem(
        statusCode: StatusCodes.Status400BadRequest, title: "Invalid request",
        detail: $"A passkey name must be 1-{WebAuthnOptions.NameMaxLength} characters without control characters.");

    private static IResult RegistrationFailed() => Results.Problem(
        statusCode: StatusCodes.Status400BadRequest, title: "Invalid request", detail: "The passkey could not be verified.");

    private static IResult RegistrationExpired() => Results.Problem(
        statusCode: StatusCodes.Status410Gone, title: "Gone", detail: "The passkey registration expired or was already used. Start again.");

    private static IResult PasskeyNotFound() => Results.Problem(
        statusCode: StatusCodes.Status404NotFound, title: "Not found", detail: "Passkey not found.");

    private static IResult SignInFailed() => Results.Problem(
        statusCode: StatusCodes.Status401Unauthorized, title: "Unauthorized", detail: "Passkey sign-in failed.");

    private static IResult PayloadTooLarge() => Results.Problem(
        statusCode: StatusCodes.Status413PayloadTooLarge, title: "Payload too large", detail: "Request body exceeds the allowed size.");

    private static IResult CapacityUnavailable(HttpContext http)
    {
        http.Response.Headers.RetryAfter = "1";
        return Results.Problem(
            statusCode: StatusCodes.Status503ServiceUnavailable, title: "Service unavailable", detail: "Service temporarily unavailable. Try again later.");
    }

    private static IResult TooManyRequests(HttpContext http, TimeSpan? retryAfter)
    {
        var seconds = retryAfter is { } r ? (int)Math.Ceiling(r.TotalSeconds) : 0;
        if (seconds > 0)
        {
            http.Response.Headers.RetryAfter = seconds.ToString(System.Globalization.CultureInfo.InvariantCulture);
        }

        return Results.Problem(statusCode: StatusCodes.Status429TooManyRequests, title: "Too Many Requests", detail: "Too many requests. Try again later.");
    }

    private static async ValueTask<object?> RejectOversizedSmallBody(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
        => context.HttpContext.Request.ContentLength is > MaxSmallBodyBytes ? PayloadTooLarge() : await next(context);

    private static async ValueTask<object?> RejectOversizedCredentialBody(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
        => context.HttpContext.Request.ContentLength is > MaxCredentialBodyBytes ? PayloadTooLarge() : await next(context);

    private static bool TryGetAccountId(ClaimsPrincipal user, out Guid accountId)
        => Guid.TryParse(user.FindFirst("sub")?.Value, out accountId) && accountId != Guid.Empty
           && Guid.TryParse(user.FindFirst("sid")?.Value, out var sessionId) && sessionId != Guid.Empty;

    /// <summary>The credential as the raw JSON object the browser sent, or null when it is not an object.</summary>
    private static string? CredentialJson(JsonElement credential)
        => credential.ValueKind == JsonValueKind.Object ? credential.GetRawText() : null;

    /// <summary>The library's options JSON, embedded verbatim in the response.</summary>
    private static JsonElement Options(string optionsJson)
    {
        using var document = JsonDocument.Parse(optionsJson);
        return document.RootElement.Clone();
    }

    private static string? TrimUserAgent(string? userAgent)
        => string.IsNullOrWhiteSpace(userAgent) ? null : (userAgent.Length > UserAgentMaxLength ? userAgent[..UserAgentMaxLength] : userAgent);

    private static PasskeyResponse ToResponse(Application.Abstractions.Persistence.StoredPasskey p)
        => new(p.Id, p.Name, p.CreatedAt, p.LastUsedAt, p.BackedUp);

    /// <summary>The same defense-in-depth jitter as the other sign-in steps; an unexpected jitter failure fails closed.</summary>
    private static async Task<IResult?> JitterAsync(HttpContext http, ILoginResponseJitter jitter, CancellationToken ct)
    {
        try
        {
            await jitter.ApplyAsync(ct);
            return null;
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch
        {
            return CapacityUnavailable(http);
        }
    }

    private static IResult SignInResult(HttpContext http, LoginResult result) => result.Outcome switch
    {
        LoginOutcome.Succeeded => Results.Ok(new TokenResponse(
            result.AccessToken!, result.AccessTokenExpiresAt, result.RefreshToken!, result.RefreshTokenExpiresAt)),
        LoginOutcome.RateLimited => TooManyRequests(http, result.RetryAfter),
        LoginOutcome.TemporarilyUnavailable => Results.Problem(
            statusCode: StatusCodes.Status503ServiceUnavailable, title: "Service unavailable", detail: "Service temporarily unavailable."),
        _ => SignInFailed(),
    };

    public static IEndpointRouteBuilder MapPasskeyEndpoints(this IEndpointRouteBuilder app)
    {
        MapAccountPasskeys(app.MapGroup("/v1/account/passkeys").WithTags("Account").RequireAuthorization());
        MapPasskeySignIn(app.MapGroup("/v1/auth").WithTags("Auth"));
        return app;
    }

    private static void MapAccountPasskeys(RouteGroupBuilder group)
    {
        group.MapGet("", async (HttpContext http, IPasskeyManagementService service, CancellationToken ct) =>
        {
            if (!TryGetAccountId(http.User, out var accountId)) return Unauthenticated();
            var passkeys = await service.ListAsync(accountId, ct);
            return Results.Ok(new PasskeyListResponse(passkeys.Select(ToResponse).ToList(), WebAuthnOptions.MaxPasskeysPerAccount));
        }).WithName("PasskeyList");

        group.MapPost("/registration/options", async (PasskeyRegistrationOptionsRequest request, HttpContext http, IPasskeyManagementService service, CancellationToken ct) =>
        {
            if (!TryGetAccountId(http.User, out var accountId)) return Unauthenticated();
            PasskeyRegistrationBegin result;
            try
            {
                result = await service.BeginRegistrationAsync(accountId, request.Password, request.Code, ct);
            }
            catch (PasswordHashingCapacityExceededException)
            {
                return CapacityUnavailable(http);
            }

            return result.Outcome switch
            {
                PasskeyRegistrationBeginOutcome.Started => Results.Ok(new PasskeyRegistrationOptionsResponse(result.RegistrationId!, Options(result.OptionsJson!))),
                PasskeyRegistrationBeginOutcome.TwoFactorRequired => TwoFactorRequired(),
                PasskeyRegistrationBeginOutcome.LimitReached => LimitReached(),
                _ => ConfirmationFailed(),
            };
        })
        .AddEndpointFilter(AuthRateLimiting.TotpManagePerAccountFilter)
        .AddEndpointFilter(RejectOversizedSmallBody)
        .WithName("PasskeyRegistrationOptions");

        group.MapPost("/registration", async (PasskeyRegistrationRequest request, HttpContext http, IPasskeyManagementService service, CancellationToken ct) =>
        {
            if (!TryGetAccountId(http.User, out var accountId)) return Unauthenticated();
            var credential = CredentialJson(request.Credential);
            if (credential is null) return RegistrationFailed();

            var result = await service.CompleteRegistrationAsync(accountId, request.RegistrationId, request.Name, credential, ct);
            return result.Outcome switch
            {
                PasskeyRegistrationOutcome.Created => Results.Json(
                    new PasskeyCreatedResponse(result.Passkey!.Id, result.Passkey.Name, result.Passkey.CreatedAt, result.Passkey.BackedUp),
                    statusCode: StatusCodes.Status201Created),
                PasskeyRegistrationOutcome.InvalidName => InvalidName(),
                PasskeyRegistrationOutcome.Expired => RegistrationExpired(),
                PasskeyRegistrationOutcome.LimitReached => LimitReached(),
                PasskeyRegistrationOutcome.TwoFactorRequired => TwoFactorRequired(),
                _ => RegistrationFailed(),
            };
        })
        .AddEndpointFilter(AuthRateLimiting.TotpManagePerAccountFilter)
        .AddEndpointFilter(RejectOversizedCredentialBody)
        .WithName("PasskeyRegistration");

        // {id:guid}: a malformed id does not match the route (404), and ownership is checked by the store (404 for
        // another account's passkey as for an unknown one). Rename is PATCH /{id} and, for browsers, POST /{id}/rename:
        // the CORS policy allows GET/POST/PUT/DELETE only, so a cross-origin PATCH never passes the preflight.
        static async Task<IResult> Rename(Guid id, PasskeyRenameRequest request, HttpContext http, IPasskeyManagementService service, CancellationToken ct)
        {
            if (!TryGetAccountId(http.User, out var accountId)) return Unauthenticated();
            return await service.RenameAsync(accountId, id, request.Name, ct) switch
            {
                PasskeyChangeOutcome.Succeeded => Results.NoContent(),
                PasskeyChangeOutcome.InvalidName => InvalidName(),
                _ => PasskeyNotFound(),
            };
        }

        group.MapPatch("/{id:guid}", Rename)
            .AddEndpointFilter(AuthRateLimiting.TotpManagePerAccountFilter)
            .AddEndpointFilter(RejectOversizedSmallBody)
            .WithName("PasskeyRename");

        group.MapPost("/{id:guid}/rename", Rename)
            .AddEndpointFilter(AuthRateLimiting.TotpManagePerAccountFilter)
            .AddEndpointFilter(RejectOversizedSmallBody)
            .WithName("PasskeyRenamePost");

        group.MapPost("/{id:guid}/delete", async (Guid id, PasskeyDeleteRequest request, HttpContext http, IPasskeyManagementService service, CancellationToken ct) =>
        {
            if (!TryGetAccountId(http.User, out var accountId)) return Unauthenticated();
            PasskeyChangeOutcome outcome;
            try
            {
                outcome = await service.DeleteAsync(accountId, id, request.Password, request.Code, ct);
            }
            catch (PasswordHashingCapacityExceededException)
            {
                return CapacityUnavailable(http);
            }

            return outcome switch
            {
                PasskeyChangeOutcome.Succeeded => Results.NoContent(),
                PasskeyChangeOutcome.NotFound => PasskeyNotFound(),
                _ => ConfirmationFailed(),
            };
        })
        .AddEndpointFilter(AuthRateLimiting.TotpManagePerAccountFilter)
        .AddEndpointFilter(RejectOversizedSmallBody)
        .WithName("PasskeyDelete");
    }

    private static void MapPasskeySignIn(RouteGroupBuilder group)
    {
        // Second sign-in step, UNAUTHENTICATED: the account comes from the challenge token of the password step.
        group.MapPost("/login/passkey/options", async (PasskeyMfaOptionsRequest request, IPasskeyLoginService service, CancellationToken ct) =>
        {
            var options = await service.BeginSecondFactorAsync(request.MfaToken, ct);
            return options is null ? SignInFailed() : Results.Ok(new PasskeyMfaOptionsResponse(Options(options.OptionsJson)));
        })
        .AddEndpointFilter(AuthRateLimiting.MfaPerIpFilter)
        .AddEndpointFilter(RejectOversizedSmallBody)
        .WithName("LoginPasskeyOptions");

        group.MapPost("/login/passkey", async (PasskeyMfaLoginRequest request, HttpContext http, IPasskeyLoginService service, ILoginResponseJitter jitter, CancellationToken ct) =>
        {
            var credential = CredentialJson(request.Credential);
            var result = credential is null
                ? LoginResult.InvalidCredentials
                : await service.CompleteSecondFactorAsync(new PasskeyMfaLoginCommand(request.MfaToken, credential), ct);
            return await JitterAsync(http, jitter, ct) ?? SignInResult(http, result);
        })
        // Order: per-IP → 16 KiB body → service (per-account limit once the challenge names the account), as /login/totp.
        .AddEndpointFilter(AuthRateLimiting.MfaPerIpFilter)
        .AddEndpointFilter(RejectOversizedCredentialBody)
        .WithName("LoginPasskey");

        // Sign-in without email and password, UNAUTHENTICATED and anonymous: the options reveal nothing about any account.
        group.MapPost("/passkey/options", async (IPasskeyLoginService service, CancellationToken ct) =>
        {
            var options = await service.BeginPasswordlessAsync(ct);
            return Results.Ok(new PasskeyLoginOptionsResponse(options.AssertionId!, Options(options.OptionsJson)));
        })
        .AddEndpointFilter(AuthRateLimiting.PasskeyPerAddressFilter)
        .AddEndpointFilter(RejectOversizedSmallBody)
        .WithName("PasskeyLoginOptions");

        group.MapPost("/passkey", async (PasskeyLoginRequest request, HttpContext http, IPasskeyLoginService service, ILoginResponseJitter jitter, CancellationToken ct) =>
        {
            var credential = CredentialJson(request.Credential);
            var result = credential is null
                ? LoginResult.InvalidCredentials
                : await service.CompletePasswordlessAsync(
                    new PasskeyLoginCommand(request.AssertionId, credential, TrimUserAgent(http.Request.Headers.UserAgent.ToString())), ct);
            return await JitterAsync(http, jitter, ct) ?? SignInResult(http, result);
        })
        .AddEndpointFilter(AuthRateLimiting.PasskeyPerAddressFilter)
        .AddEndpointFilter(RejectOversizedCredentialBody)
        .WithName("PasskeyLogin");
    }
}
