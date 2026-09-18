using BitosX.Application.Sessions;
using Microsoft.AspNetCore.Authentication.JwtBearer;

namespace BitosX.Api.Auth;

/// <summary>
/// The single per-request authorization seam. JwtBearer performs all JWT crypto/claims validation
/// (signature, <c>iss</c>/<c>aud</c>/<c>exp</c>/skew, HS256-only, mandatory-kid resolution) against the
/// shared <c>TokenValidationParameters</c>; this runs afterwards in <c>OnTokenValidated</c> and adds only
/// the authoritative session-state check via <see cref="ISessionAuthenticator"/>. It is NOT a bespoke
/// bearer handler and does no JWT crypto. Any failure fails the context, yielding a generic 401 — no
/// reason detail is ever surfaced (anti-enumeration / no session-state disclosure).
/// </summary>
public static class SessionValidation
{
    public static async Task ValidateAsync(TokenValidatedContext context)
    {
        var principal = context.Principal;

        // With MapInboundClaims = false the claims keep their raw JWT names.
        if (principal is null
            || !Guid.TryParse(principal.FindFirst("sub")?.Value, out var accountId)
            || !Guid.TryParse(principal.FindFirst("sid")?.Value, out var sessionId)
            || accountId == Guid.Empty
            || sessionId == Guid.Empty)
        {
            context.Fail("Invalid token.");
            return;
        }

        var authenticator = context.HttpContext.RequestServices.GetRequiredService<ISessionAuthenticator>();
        var result = await authenticator.AuthenticateAsync(accountId, sessionId, context.HttpContext.RequestAborted);
        if (result != SessionAuthResult.Valid)
        {
            context.Fail("Invalid session.");
        }
    }
}
