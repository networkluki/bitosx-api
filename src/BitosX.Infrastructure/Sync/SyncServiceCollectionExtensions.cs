using BitosX.Application.Abstractions.Persistence;
using BitosX.Application.Sync;
using BitosX.Infrastructure.Persistence;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace BitosX.Infrastructure.Sync;

/// <summary>
/// Composes encrypted-envelope sync. It rides on the Login capability (every endpoint is
/// authenticated by the session JWT) and adds the envelope store and the sync service. Limits are
/// bound from <c>Security:Sync</c> and validated fail-closed.
/// </summary>
public static class SyncServiceCollectionExtensions
{
    public static IServiceCollection AddBitosxVaultSync(
        this IServiceCollection services, IConfiguration configuration, string runtimeConnectionString)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);
        if (string.IsNullOrWhiteSpace(runtimeConnectionString))
        {
            throw new ArgumentException("A non-blank runtime connection string is required for sync.", nameof(runtimeConnectionString));
        }

        var options = new VaultSyncOptions();
        configuration.GetSection(VaultSyncOptions.SectionName).Bind(options);
        options.Validate();

        var connectionFactory = new BitosxConnectionFactory(runtimeConnectionString);
        if (!services.Any(d => d.ServiceType == typeof(TimeProvider)))
        {
            services.AddSingleton(TimeProvider.System);
        }

        services.AddSingleton(options);
        services.AddSingleton<IEnvelopeStore>(sp => new EnvelopeStore(connectionFactory, sp.GetRequiredService<TimeProvider>()));
        services.AddScoped<IVaultSyncService, VaultSyncService>();
        return services;
    }
}
