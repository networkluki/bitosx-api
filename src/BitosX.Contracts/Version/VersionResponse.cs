namespace BitosX.Contracts.Version;

/// <summary>
/// Response for <c>GET /version</c>.
/// Carries only non-sensitive product/build information. It must never expose
/// host details, paths, environment, configuration, or any secret.
/// </summary>
/// <param name="Service">Stable product name, e.g. "BitosX API".</param>
/// <param name="Version">Informational product/build version, e.g. "0.1.0".</param>
public sealed record VersionResponse(string Service, string Version);
