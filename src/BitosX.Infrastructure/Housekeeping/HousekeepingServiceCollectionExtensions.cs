using BitosX.Application.Abstractions.Persistence;
using BitosX.Application.Housekeeping;
using BitosX.Application.Security;
using BitosX.Infrastructure.Persistence;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace BitosX.Infrastructure.Housekeeping;

public static class HousekeepingServiceCollectionExtensions
{
    /// <summary>
    /// Binds and validates <c>Housekeeping</c> (fail closed) and, unless disabled, registers the background
    /// pruning of dead challenges and sessions over the runtime (DML) connection. Composed with AccountCore: the
    /// tables exist whatever optional capability is on. The session idle lifetime comes from the Login
    /// configuration when it is registered, else the default.
    /// </summary>
    public static IServiceCollection AddBitosxHousekeeping(this IServiceCollection services, IConfiguration configuration, string runtimeConnectionString)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);
        if (string.IsNullOrWhiteSpace(runtimeConnectionString))
        {
            throw new ArgumentException("A non-blank runtime connection string is required for housekeeping.", nameof(runtimeConnectionString));
        }

        var options = new HousekeepingOptions();
        configuration.GetSection(HousekeepingOptions.SectionName).Bind(options);
        options.Validate();

        var connectionFactory = new BitosxConnectionFactory(runtimeConnectionString);
        services.AddSingleton(options);
        if (!services.Any(d => d.ServiceType == typeof(TimeProvider)))
        {
            services.AddSingleton(TimeProvider.System);
        }

        services.AddSingleton<IHousekeepingStore>(_ => new HousekeepingStore(connectionFactory));
        services.AddSingleton(sp => new HousekeepingRunner(
            sp.GetRequiredService<IHousekeepingStore>(),
            options,
            sp.GetService<RefreshTokenOptions>() ?? new RefreshTokenOptions(),
            sp.GetRequiredService<TimeProvider>(),
            sp.GetRequiredService<ILogger<HousekeepingRunner>>()));

        if (options.Enabled)
        {
            services.AddHostedService<HousekeepingBackgroundService>();
        }

        return services;
    }
}
