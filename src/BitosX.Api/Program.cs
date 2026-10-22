using System.Net;
using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;
using BitosX.Api.Auth;
using BitosX.Api.Endpoints;
using BitosX.Api.Http;
using BitosX.Api.Security;
using BitosX.Application.Versioning;
using BitosX.Infrastructure.Accounts;
using BitosX.Infrastructure.Persistence;
using BitosX.Infrastructure.Security;
using BitosX.Infrastructure.Sync;
using BitosX.Infrastructure.Versioning;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Extensions.Logging;

var builder = WebApplication.CreateBuilder(args);

// ---- Logging: structured, single-line console with correlation scope ----
builder.Logging.ClearProviders();
builder.Logging.AddSimpleConsole(options =>
{
    options.IncludeScopes = true;
    options.SingleLine = true;
});

// ---- JSON: explicit, deterministic camelCase; omit nulls ----
builder.Services.ConfigureHttpJsonOptions(options =>
{
    options.SerializerOptions.PropertyNamingPolicy = JsonNamingPolicy.CamelCase;
    options.SerializerOptions.DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull;
    options.SerializerOptions.WriteIndented = false;
});

// ---- RFC7807 ProblemDetails for all error responses ----
builder.Services.AddProblemDetails();

// ---- OpenAPI document (served at /openapi/v1.json) — DEVELOPMENT ONLY ----
// Never registered or mapped in Production: the document (and any future interactive explorer) would leak
// API shape. Enabling it in Production is a separate, explicit future security decision (Phase 2D.3).
if (builder.Environment.IsDevelopment())
{
    builder.Services.AddOpenApi();
}

// ---- Forwarded headers: trust ONLY the local Apache reverse proxy (Phase 2D.1 client-IP model) ----
// Production path is Cloudflare -> Apache -> Kestrel (loopback); Apache establishes the Cloudflare
// trust boundary and normalizes the client address before proxying over loopback. Kestrel processes
// exactly one hop of X-Forwarded-For/-Proto and trusts only the loopback proxy, so an incoming
// X-Forwarded-For from any non-loopback peer is never honored. KnownProxies/KnownIPNetworks are NOT
// cleared: the framework's loopback defaults are retained and loopback is added explicitly.
builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
    options.ForwardLimit = 1;
    options.KnownProxies.Add(IPAddress.Loopback);      // 127.0.0.1
    options.KnownProxies.Add(IPAddress.IPv6Loopback);  // ::1
});

// ---- Kestrel: conservative request-body-size limit ----
// No current endpoint accepts a body; future endpoints can raise this locally.
builder.WebHost.ConfigureKestrel(options =>
{
    options.Limits.MaxRequestBodySize = 64 * 1024; // 64 KB
    options.AddServerHeader = false;
});

// ---- CORS for the browser client(s): the web account app at https://vault.bitosx.se ----
// Bound + validated fail-closed at startup (exact https origins only, no credentials).
// With an empty Security:Cors:AllowedOrigins list, no CORS middleware is registered and no
// CORS header is emitted, exactly as before. See BrowserCorsOptions for the policy and its rationale.
var corsOptions = BrowserCorsOptions.Bind(builder.Configuration);
builder.Services.AddSingleton(corsOptions);
if (corsOptions.Enabled)
{
    builder.Services.AddCors(options => options.AddPolicy(BrowserCorsOptions.PolicyName, corsOptions.BuildPolicy()));
}

// ---- Composition root ----
// Product version is derived from this API assembly's build metadata.
builder.Services.AddSingleton<IProductVersionProvider>(
    _ => new AssemblyProductVersionProvider(Assembly.GetExecutingAssembly()));

// Persistence is wired only when a connection string is configured (from a
// local secret store, never committed). It stays absent for the loopback
// health/version foundation, and no auth/account behavior is exposed yet.
// Capability-based composition (detected once). AccountCore is independent of SMTP;
// EmailVerification adds register/verify/resend + outbox; EmailDelivery adds the SMTP
// sender + dispatcher. A missing optional capability disables only itself.
var bitosxConnectionString = builder.Configuration.GetConnectionString("Bitosx");
var capabilities = AccountsServiceCollectionExtensions.DetectCapabilities(builder.Configuration);
builder.Services.AddSingleton(capabilities);

// Fail closed in Production on an unsafe public-exposure posture: Login without hardening, or a
// wildcard/public Kestrel listener. No-op in Development/Test. (Phase 2D.3)
ProductionExposureValidation.Validate(builder.Environment, builder.Configuration, capabilities);

if (capabilities.AccountCoreEnabled)
{
    var bitosxMigratorConnectionString = builder.Configuration.GetConnectionString("BitosxMigrator");
    builder.Services.AddBitosxPersistence(bitosxConnectionString!, bitosxMigratorConnectionString);
    builder.Services.AddBitosxAccountCore(builder.Configuration);

    // Phase 2D.1: bind + validate public-exposure hardening (fail-closed) and register the auth rate
    // limiters. Inert unless Security:PublicExposureHardening:Enabled is true. Composed with AccountCore
    // (not Login) because the forgot/reset-password limiters ride on EmailVerification alone.
    builder.Services.AddPublicExposureHardening(builder.Configuration);

    if (capabilities.EmailVerificationEnabled)
    {
        builder.Services.AddBitosxEmailVerification(builder.Configuration, bitosxConnectionString!);
    }

    // EmailDelivery (SMTP sender + background dispatcher) is registered ONLY when SMTP
    // credentials are present. When absent, no dispatcher runs and no queued mail is
    // attempted.
    if (capabilities.EmailDeliveryEnabled)
    {
        builder.Services.AddBitosxEmailDelivery(builder.Configuration);
    }

    // Login (access-JWT issuance + refresh + sessions) is an independent capability, enabled only
    // when the current JWT signing key is configured. JwtBearer performs the JWT crypto/claims
    // validation from the SINGLE shared validation-parameters source; the per-request session-state
    // check is the one OnTokenValidated seam (never scattered across endpoints).
    if (capabilities.LoginEnabled)
    {
        builder.Services.AddBitosxLogin(builder.Configuration, bitosxConnectionString!);

        // Encrypted-envelope sync rides on Login: every sync endpoint is authenticated by the session JWT.
        // The server stores the desktop vault file as opaque ciphertext; limits are validated fail-closed.
        builder.Services.AddBitosxVaultSync(builder.Configuration, bitosxConnectionString!);

        builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer();
        builder.Services.AddOptions<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme)
            .Configure<JwtTokenValidationParametersFactory>((options, factory) =>
            {
                options.MapInboundClaims = false; // keep raw sub/sid claim names for the session seam
                options.TokenValidationParameters = factory.Create();
                options.Events = new JwtBearerEvents { OnTokenValidated = SessionValidation.ValidateAsync };
            });
        builder.Services.AddAuthorization();
    }
}

var app = builder.Build();

// Production-safe error handling. The developer exception page is never
// enabled: clients only ever receive RFC7807 ProblemDetails, never stack traces.
app.UseExceptionHandler();

// Trust loopback-only forwarded headers (see ForwardedHeadersOptions above).
app.UseForwardedHeaders();

// Correlation id + scoped logging (does not log headers or bodies).
app.UseMiddleware<CorrelationIdMiddleware>();

// CORS runs before authentication so a browser preflight (OPTIONS, no credentials) is answered
// without ever reaching an endpoint, its rate limiter or the JWT handler. Registered only when an
// origin is configured; a disallowed Origin simply gets no CORS headers and the browser blocks the read.
if (corsOptions.Enabled)
{
    app.UseCors(BrowserCorsOptions.PolicyName);
}

// Per-endpoint request-body limit (the envelope upload needs more than Kestrel's 64 KB default).
app.UseMiddleware<MaxRequestBodySizeMiddleware>();

// Authentication/authorization run only when the Login capability is enabled (otherwise no
// authentication scheme is registered and the middleware would have nothing to do).
if (capabilities.LoginEnabled)
{
    app.UseAuthentication();
    app.UseAuthorization();
}

// OpenAPI document is mapped ONLY in Development (see AddOpenApi gating above). In Production the route
// is absent → a request returns normal 404, never an API document.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

// Unversioned infrastructure endpoints (/health, /version).
app.MapInfrastructureEndpoints();

// Future versioned business API surface (currently empty).
app.MapApiV1();

// Auth endpoints are exposed when EmailVerification is available. register/resend/forgot-password
// return a generic 503 when EmailDelivery is unavailable (routes stay mapped); verify-email and
// reset-password remain available so already-issued links can be consumed.
if (capabilities.EmailVerificationEnabled)
{
    app.MapAuthEndpoints();
}

// Login + protected account endpoints are mapped only when the Login capability is enabled —
// independent of EmailVerification.
if (capabilities.LoginEnabled)
{
    app.MapLoginEndpoints();
    app.MapAccountEndpoints();
    app.MapSyncEndpoints();
}

// Capability state is logged safely at startup (booleans only, no secrets) and is
// deliberately NOT exposed on the public /health endpoint.
app.Logger.LogInformation(
    "BitosX account capabilities: AccountCore={AccountCore} EmailVerification={EmailVerification} EmailDelivery={EmailDelivery} Login={Login}",
    capabilities.AccountCoreEnabled, capabilities.EmailVerificationEnabled, capabilities.EmailDeliveryEnabled, capabilities.LoginEnabled);

// Extensibility seam for endpoint contributions registered in DI. No modules
// are registered in production; integration tests use this to exercise the
// production error pipeline.
foreach (var mapEndpoints in app.Services.GetServices<Action<IEndpointRouteBuilder>>())
{
    mapEndpoints(app);
}

app.Run();

// Exposed so the integration test project can bootstrap the app with
// WebApplicationFactory<Program>.
public partial class Program;
