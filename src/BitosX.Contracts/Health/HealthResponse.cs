namespace BitosX.Contracts.Health;

/// <summary>
/// Liveness response for <c>GET /health</c>.
/// This is a pure liveness signal: it does not report database or dependency
/// readiness (there is no database in this milestone).
/// </summary>
/// <param name="Service">Stable product name, e.g. "BitosX API".</param>
/// <param name="Status">Liveness status, e.g. "healthy".</param>
public sealed record HealthResponse(string Service, string Status);
