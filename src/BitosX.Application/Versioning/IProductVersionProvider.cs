namespace BitosX.Application.Versioning;

/// <summary>
/// Supplies the current product/build version. Implemented in Infrastructure
/// so the Application layer stays free of assembly/reflection concerns.
/// </summary>
public interface IProductVersionProvider
{
    /// <summary>
    /// Returns a clean, non-sensitive product version (e.g. "0.1.0").
    /// </summary>
    string GetProductVersion();
}
