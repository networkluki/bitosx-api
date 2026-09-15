namespace BitosX.Api.Http;

/// <summary>
/// Assigns a correlation identifier to every request, echoes it back in the
/// <c>X-Correlation-ID</c> response header, and adds it to the logging scope.
///
/// It deliberately does not log request/response headers or bodies: those may
/// carry credentials or vault-adjacent data and are out of scope for logging.
/// </summary>
public sealed class CorrelationIdMiddleware
{
    public const string HeaderName = "X-Correlation-ID";
    private const int MaxClientIdLength = 128;

    private readonly RequestDelegate _next;
    private readonly ILogger<CorrelationIdMiddleware> _logger;

    public CorrelationIdMiddleware(RequestDelegate next, ILogger<CorrelationIdMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var correlationId = ResolveCorrelationId(context);

        // Make it discoverable to handlers and to the client.
        context.TraceIdentifier = correlationId;
        context.Response.OnStarting(() =>
        {
            context.Response.Headers[HeaderName] = correlationId;
            return Task.CompletedTask;
        });

        using (_logger.BeginScope(new Dictionary<string, object> { ["CorrelationId"] = correlationId }))
        {
            await _next(context);
        }
    }

    private static string ResolveCorrelationId(HttpContext context)
    {
        if (context.Request.Headers.TryGetValue(HeaderName, out var provided))
        {
            var candidate = provided.ToString();
            if (IsAcceptable(candidate))
            {
                return candidate;
            }
        }

        return context.TraceIdentifier is { Length: > 0 } existing
            ? existing
            : Guid.NewGuid().ToString("n");
    }

    // Accept only a short, printable-ASCII token so a client cannot inject
    // control characters / header-splitting sequences into logs or responses.
    private static bool IsAcceptable(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > MaxClientIdLength)
        {
            return false;
        }

        foreach (var c in value)
        {
            if (c is < ' ' or > '~')
            {
                return false;
            }
        }

        return true;
    }
}
