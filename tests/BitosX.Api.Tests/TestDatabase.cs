using Microsoft.Extensions.Configuration;

namespace BitosX.Api.Tests;

/// <summary>
/// The isolated test database's connection string, read exactly like the Infrastructure tests' fixture does:
/// local user-secrets (UserSecretsId <c>bitosx-infrastructure-tests</c>), overridden by the environment variable
/// <c>ConnectionStrings__BitosxTest</c> (CI and the MariaDB test runs set it). Never committed.
/// </summary>
internal static class TestDatabase
{
    private static readonly Lazy<IConfiguration> Configuration = new(() => new ConfigurationBuilder()
        .AddUserSecrets("bitosx-infrastructure-tests")
        .AddEnvironmentVariables()
        .Build());

    public static string ConnectionString
        => Configuration.Value.GetConnectionString("BitosxTest") is { Length: > 0 } value
            ? value
            : throw new InvalidOperationException(
                "ConnectionStrings:BitosxTest not configured for tests (user-secrets 'bitosx-infrastructure-tests' " +
                "or the environment variable ConnectionStrings__BitosxTest).");
}
