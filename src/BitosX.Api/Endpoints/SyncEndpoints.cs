using System.Security.Claims;
using BitosX.Api.Security;
using BitosX.Application.Abstractions.Persistence;
using BitosX.Application.Sync;
using BitosX.Contracts.Sync;
using Microsoft.AspNetCore.Http.Features;

namespace BitosX.Api.Endpoints;

/// <summary>
/// Encrypted-envelope sync (<c>/v1/sync</c>), mapped only when the Login capability is enabled and
/// requiring authentication. The envelope is the desktop vault file: ciphertext under a key the
/// server never has. These handlers move bytes and metadata; identity comes from the validated JWT,
/// the compare-and-set revision rule lives in the store, and the shape check in the service.
/// </summary>
public static class SyncEndpoints
{
    private static IResult Unauthenticated() => Results.Problem(
        statusCode: StatusCodes.Status401Unauthorized, title: "Unauthorized", detail: "Authentication required.");

    private static IResult NothingStored() => Results.Problem(
        statusCode: StatusCodes.Status404NotFound, title: "Not found", detail: "No envelope is stored for this account.");

    private static bool TryGetAccountId(ClaimsPrincipal user, out Guid accountId)
        => Guid.TryParse(user.FindFirst("sub")?.Value, out accountId) && accountId != Guid.Empty;

    private static string Hex(byte[] fingerprint) => Convert.ToHexStringLower(fingerprint);

    public static IEndpointRouteBuilder MapSyncEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/v1/sync").WithTags("Sync").RequireAuthorization();

        group.MapGet("/status", async (HttpContext http, IVaultSyncService sync, CancellationToken ct) =>
        {
            if (!TryGetAccountId(http.User, out var accountId))
            {
                return Unauthenticated();
            }

            StoredEnvelope? stored = await sync.GetStatusAsync(accountId, ct);
            return stored is null
                ? NothingStored()
                : Results.Ok(new SyncStatusResponse(stored.Revision, Hex(stored.Fingerprint), stored.SizeBytes, stored.UpdatedAt));
        }).WithName("SyncStatus");

        group.MapGet("/envelope", async (HttpContext http, IVaultSyncService sync, CancellationToken ct) =>
        {
            if (!TryGetAccountId(http.User, out var accountId))
            {
                return Unauthenticated();
            }

            StoredEnvelope? stored = await sync.DownloadAsync(accountId, ct);
            if (stored?.Envelope is null)
            {
                return NothingStored();
            }

            http.Response.Headers.CacheControl = "no-store";
            return Results.Ok(new SyncEnvelopeResponse(
                stored.Revision, Hex(stored.Fingerprint), stored.SizeBytes, stored.UpdatedAt, Convert.ToBase64String(stored.Envelope)));
        }).WithName("SyncDownload");

        group.MapPut("/envelope", async (SyncUploadRequest request, HttpContext http, IVaultSyncService sync, VaultSyncOptions options, CancellationToken ct) =>
        {
            if (!TryGetAccountId(http.User, out var accountId))
            {
                return Unauthenticated();
            }

            if (request.BaseRevision < 0)
            {
                return Results.Problem(statusCode: StatusCodes.Status400BadRequest, title: "Bad request", detail: "baseRevision must be 0 or a revision the server issued.");
            }

            // The Base64 text is bounded by the body limit; the decoded size is checked by the service.
            if (string.IsNullOrEmpty(request.Envelope) || request.Envelope.Length > options.MaxUploadBodyBytes)
            {
                return Results.Problem(statusCode: StatusCodes.Status400BadRequest, title: "Bad request", detail: "envelope is missing or too large.");
            }

            byte[] envelope;
            try
            {
                envelope = Convert.FromBase64String(request.Envelope);
            }
            catch (FormatException)
            {
                return Results.Problem(statusCode: StatusCodes.Status400BadRequest, title: "Bad request", detail: "envelope is not valid Base64.");
            }

            SyncUploadResult result = await sync.UploadAsync(accountId, request.BaseRevision, envelope, ct);
            return result.Outcome switch
            {
                SyncUploadOutcome.Stored => Results.Ok(new SyncUploadResponse(result.Revision, Hex(result.Fingerprint!), result.SizeBytes, result.UpdatedAt)),
                SyncUploadOutcome.Conflict => Results.Problem(
                    statusCode: StatusCodes.Status409Conflict, title: "Conflict",
                    detail: "The server holds a revision this client has not seen. Download it first, or upload against the current revision.",
                    extensions: new Dictionary<string, object?> { ["currentRevision"] = result.Revision }),
                SyncUploadOutcome.TooLarge => Results.Problem(statusCode: StatusCodes.Status413PayloadTooLarge, title: "Payload too large", detail: "The envelope exceeds the size limit."),
                SyncUploadOutcome.InvalidEnvelope => Results.Problem(statusCode: StatusCodes.Status400BadRequest, title: "Bad request", detail: "envelope is not a BitosX vault envelope."),
                _ => Unauthenticated(), // the account is gone: fail closed like any other dead session
            };
        })
        .AddEndpointFilter(AuthRateLimiting.SyncWritePerAccountFilter)
        .WithMetadata(new MaxRequestBodySizeMetadata(MaxRequestBodySizeMetadata.FromSync))
        .WithName("SyncUpload");

        group.MapDelete("/envelope", async (HttpContext http, IVaultSyncService sync, CancellationToken ct) =>
        {
            if (!TryGetAccountId(http.User, out var accountId))
            {
                return Unauthenticated();
            }

            await sync.DeleteAsync(accountId, ct);
            return Results.NoContent(); // idempotent: deleting nothing is still "nothing stored"
        })
        .AddEndpointFilter(AuthRateLimiting.SyncWritePerAccountFilter)
        .WithName("SyncDelete");

        return app;
    }
}

/// <summary>
/// Raises the request-body limit for one endpoint above Kestrel's conservative default (64 KB). The
/// limit is taken from <see cref="VaultSyncOptions"/> at request time, so the two can never disagree.
/// Applied by <see cref="MaxRequestBodySizeMiddleware"/> before the body is read.
/// </summary>
public sealed class MaxRequestBodySizeMetadata
{
    public static readonly Func<IServiceProvider, long> FromSync =
        services => services.GetRequiredService<VaultSyncOptions>().MaxUploadBodyBytes;

    public MaxRequestBodySizeMetadata(Func<IServiceProvider, long> limit) => Limit = limit;

    public Func<IServiceProvider, long> Limit { get; }
}

/// <summary>Sets Kestrel's per-request body limit from the matched endpoint's <see cref="MaxRequestBodySizeMetadata"/>, if any.</summary>
public sealed class MaxRequestBodySizeMiddleware
{
    private readonly RequestDelegate _next;

    public MaxRequestBodySizeMiddleware(RequestDelegate next) => _next = next;

    public Task InvokeAsync(HttpContext context)
    {
        var metadata = context.GetEndpoint()?.Metadata.GetMetadata<MaxRequestBodySizeMetadata>();
        if (metadata is not null)
        {
            var feature = context.Features.Get<IHttpMaxRequestBodySizeFeature>();
            if (feature is { IsReadOnly: false })
            {
                feature.MaxRequestBodySize = metadata.Limit(context.RequestServices);
            }
        }

        return _next(context);
    }
}
