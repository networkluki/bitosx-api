using System.Reflection;
using BitosX.Application.Versioning;

namespace BitosX.Infrastructure.Versioning;

/// <summary>
/// Reads the product version from a supplied assembly's
/// <see cref="AssemblyInformationalVersionAttribute"/> (falling back to the
/// assembly version), normalized for safe public exposure.
/// </summary>
public sealed class AssemblyProductVersionProvider : IProductVersionProvider
{
    private readonly string _version;

    public AssemblyProductVersionProvider(Assembly assembly)
    {
        ArgumentNullException.ThrowIfNull(assembly);

        var informational = assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?
            .InformationalVersion;

        var raw = informational ?? assembly.GetName().Version?.ToString();

        _version = ProductVersion.Normalize(raw);
    }

    public string GetProductVersion() => _version;
}
