using BitosX.Application.Abstractions.Persistence;
using BitosX.Infrastructure.Persistence;

namespace BitosX.Api.Hosting;

/// <summary>
/// <c>dotnet BitosX.Api.dll migrate</c>: applies every pending schema migration with the schema-management
/// account (<c>ConnectionStrings:BitosxMigrator</c>) and exits — 0 on success, 1 when a migration fails, 2 when
/// the connection string is missing. The web host is never built or started, so no endpoint, background
/// service or capability check runs, and the web host itself never needs the migrator secret. Configuration
/// comes from the same sources as the web host (appsettings, user-secrets in Development, environment
/// variables, command line). Output names migrations and error types only, never a connection string.
/// </summary>
public static class MigrateCommand
{
    public const string Name = "migrate";

    public const int Success = 0;
    public const int Failed = 1;
    public const int NotConfigured = 2;

    /// <summary>True when the process was started as <c>BitosX.Api migrate [host options]</c>.</summary>
    public static bool IsRequested(string[] args)
        => args.Length > 0 && string.Equals(args[0], Name, StringComparison.Ordinal);

    /// <summary>Reads configuration exactly like the web host (the builder is never built), then migrates.</summary>
    public static Task<int> RunAsync(string[] args, TextWriter output, TextWriter error, CancellationToken cancellationToken = default)
    {
        var builder = WebApplication.CreateBuilder(args.Skip(1).ToArray());
        return RunAsync(builder.Configuration, output, error, cancellationToken);
    }

    public static Task<int> RunAsync(IConfiguration configuration, TextWriter output, TextWriter error, CancellationToken cancellationToken = default)
    {
        var connectionString = configuration.GetConnectionString("BitosxMigrator");
        if (string.IsNullOrWhiteSpace(connectionString))
        {
            error.WriteLine("migrate: ConnectionStrings:BitosxMigrator is not configured; nothing was changed.");
            return Task.FromResult(NotConfigured);
        }

        return RunAsync(new SqlMigrationRunner(new BitosxConnectionFactory(connectionString)), output, error, cancellationToken);
    }

    public static async Task<int> RunAsync(IDatabaseMigrator migrator, TextWriter output, TextWriter error, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(migrator);
        try
        {
            var applied = await migrator.ApplyMigrationsAsync(cancellationToken).ConfigureAwait(false);
            if (applied.Count == 0)
            {
                output.WriteLine("migrate: the schema is up to date; no migration was pending.");
            }
            else
            {
                foreach (var id in applied)
                {
                    output.WriteLine($"migrate: applied {id}");
                }

                output.WriteLine($"migrate: {applied.Count} migration(s) applied.");
            }

            return Success;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // The type and the driver message only (it names the database user at most, never a password).
            error.WriteLine($"migrate: failed ({ex.GetType().Name}): {ex.Message}");
            return Failed;
        }
    }
}
