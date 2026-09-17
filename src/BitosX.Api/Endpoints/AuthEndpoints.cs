using BitosX.Application.Accounts;
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

    private static IResult EmailDeliveryUnavailable() => Results.Problem(
        statusCode: StatusCodes.Status503ServiceUnavailable, title: "Service unavailable", detail: EmailUnavailable);

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
}
