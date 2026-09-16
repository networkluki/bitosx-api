using System.Net;
using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;
using BitosX.Api.Endpoints;
using BitosX.Api.Http;
using BitosX.Application.Versioning;
using BitosX.Infrastructure.Persistence;
using BitosX.Infrastructure.Versioning;
using Microsoft.AspNetCore.HttpOverrides;

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

// ---- OpenAPI document (served at /openapi/v1.json) ----
builder.Services.AddOpenApi();

// ---- Forwarded headers: trust ONLY the local Apache reverse proxy ----
// The future path is Cloudflare -> Apache -> Kestrel (loopback). Kestrel must
// never trust forwarded headers from arbitrary networks.
builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
    options.KnownIPNetworks.Clear();
    options.KnownProxies.Clear();
    options.KnownProxies.Add(IPAddress.Loopback);      // 127.0.0.1
    options.KnownProxies.Add(IPAddress.IPv6Loopback);  // ::1
    options.ForwardLimit = 1;
});

// ---- Kestrel: conservative request-body-size limit ----
// No current endpoint accepts a body; future endpoints can raise this locally.
builder.WebHost.ConfigureKestrel(options =>
{
    options.Limits.MaxRequestBodySize = 64 * 1024; // 64 KB
    options.AddServerHeader = false;
});

// ---- Composition root ----
// Product version is derived from this API assembly's build metadata.
builder.Services.AddSingleton<IProductVersionProvider>(
    _ => new AssemblyProductVersionProvider(Assembly.GetExecutingAssembly()));

// Persistence is wired only when a connection string is configured (from a
// local secret store, never committed). It stays absent for the loopback
// health/version foundation, and no auth/account behavior is exposed yet.
var bitosxConnectionString = builder.Configuration.GetConnectionString("Bitosx");
if (!string.IsNullOrWhiteSpace(bitosxConnectionString))
{
    // Runtime uses a DML-only account; the migrator (optional) uses a separate
    // schema-management account. Neither credential is committed.
    var bitosxMigratorConnectionString = builder.Configuration.GetConnectionString("BitosxMigrator");
    builder.Services.AddBitosxPersistence(bitosxConnectionString, bitosxMigratorConnectionString);
}

var app = builder.Build();

// Production-safe error handling. The developer exception page is never
// enabled: clients only ever receive RFC7807 ProblemDetails, never stack traces.
app.UseExceptionHandler();

// Trust loopback-only forwarded headers (see ForwardedHeadersOptions above).
app.UseForwardedHeaders();

// Correlation id + scoped logging (does not log headers or bodies).
app.UseMiddleware<CorrelationIdMiddleware>();

app.MapOpenApi();

// Unversioned infrastructure endpoints (/health, /version).
app.MapInfrastructureEndpoints();

// Future versioned business API surface (currently empty).
app.MapApiV1();

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
