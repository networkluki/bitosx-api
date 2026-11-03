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
    /// Registers the BitosX persistence services for the web host. The connection string is supplied by the
    /// caller from a local secret store (never committed).
    ///
    /// The runtime connection uses a DML-only database account. Schema migrations are NOT part of the web
    /// host: they are applied by the separate <c>migrate</c> command (a <see cref="SqlMigrationRunner"/> over
    /// the schema-management account), so the web host never holds credentials that could alter the schema.
    /// </summary>
    public static IServiceCollection AddBitosxPersistence(
        this IServiceCollection services,
        string runtimeConnectionString)
    {
        ConfigureDapper();

        services.AddScoped<IAccountRepository>(
            _ => new AccountRepository(new BitosxConnectionFactory(runtimeConnectionString)));

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
