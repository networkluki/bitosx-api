namespace BitosX.Application;

/// <summary>
/// Stable, non-sensitive identity of this service. Single source of truth for
/// the product name surfaced by infrastructure endpoints (/health, /version).
/// </summary>
public static class ServiceInfo
{
    /// <summary>Public product name.</summary>
    public const string Name = "BitosX API";
}
