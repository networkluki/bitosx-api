using BitosX.Application.Abstractions.Persistence;
using Dapper;
using Microsoft.Extensions.DependencyInjection;

namespace BitosX.Infrastructure.Persistence;

/// <summary>
/// Composition helpers for the BitosX MariaDB persistence layer. All DB wiring
/// lives here so the API host never references the database driver directly.
/// </summary>
public static class PersistenceServiceCollectionExtensions
{
    private static int _dapperConfigured;

    /// <summary>
    /// Registers the BitosX persistence services. Connection strings are supplied
    /// by the caller from a local secret store (never committed).
    ///
    /// The runtime connection uses a DML-only database account; the migrator uses
    /// a separate schema-management account. They are intentionally distinct so a
    /// compromise of the runtime credentials cannot alter the schema. The migrator
    /// is registered only when its connection string is provided.
    /// </summary>
    public static IServiceCollection AddBitosxPersistence(
        this IServiceCollection services,
        string runtimeConnectionString,
        string? migratorConnectionString = null)
    {
        ConfigureDapper();

        services.AddScoped<IAccountRepository>(
            _ => new AccountRepository(new BitosxConnectionFactory(runtimeConnectionString)));

        if (!string.IsNullOrWhiteSpace(migratorConnectionString))
        {
            services.AddSingleton<IDatabaseMigrator>(
                _ => new SqlMigrationRunner(new BitosxConnectionFactory(migratorConnectionString)));
        }

        return services;
    }

    private static void ConfigureDapper()
    {
        // Map snake_case columns (normalized_email) to PascalCase members.
        if (Interlocked.Exchange(ref _dapperConfigured, 1) == 0)
        {
            DefaultTypeMap.MatchNamesWithUnderscores = true;
        }
    }
}
