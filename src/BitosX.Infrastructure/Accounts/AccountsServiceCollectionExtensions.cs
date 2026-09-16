using BitosX.Application.Abstractions.Persistence;
using BitosX.Application.Accounts;
using BitosX.Application.Email;
using BitosX.Application.Security;
using BitosX.Application.Verification;
using BitosX.Infrastructure.Email;
using BitosX.Infrastructure.Persistence;
using BitosX.Infrastructure.Security;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace BitosX.Infrastructure.Accounts;

/// <summary>
/// Registers the account-registration + email-verification subsystem: password
/// hashing, token/verifier, outbox crypto, stores, services, Gmail sender, and
/// the background outbox dispatcher. All secrets come from configuration
/// (user-secrets in dev), never from source.
/// </summary>
public static class AccountsServiceCollectionExtensions
{
    public static IServiceCollection AddBitosxAccounts(
        this IServiceCollection services, IConfiguration configuration, string runtimeConnectionString)
    {
        // ---- Options bound from configuration (secrets stay in the secret store) ----
        var argon2 = new Argon2ParametersOptions();
        configuration.GetSection("Security:Argon2").Bind(argon2);

        var verification = new EmailVerificationSecurityOptions
        {
            Pepper = configuration["Security:EmailVerificationPepper"] ?? string.Empty,
        };
        var lifetimeSeconds = configuration.GetValue<int?>("Security:EmailVerification:TokenLifetimeSeconds");
        if (lifetimeSeconds is > 0) verification.TokenLifetime = TimeSpan.FromSeconds(lifetimeSeconds.Value);

        var outboxCrypto = new EmailOutboxCryptoOptions
        {
            Key = configuration["Security:EmailOutboxKey"] ?? string.Empty,
        };

        var email = new EmailOptions();
        configuration.GetSection("Email").Bind(email);

        var smtp = new SmtpOptions
        {
            Host = configuration["Email:SmtpHost"] ?? "smtp.gmail.com",
            Port = configuration.GetValue("Email:SmtpPort", 587),
            Username = configuration["Email:SmtpUsername"] ?? string.Empty,
            AppPassword = configuration["Email:SmtpAppPassword"] ?? string.Empty,
        };

        var outbox = new EmailOutboxOptions();
        configuration.GetSection("Email:Outbox").Bind(outbox);

        var connectionFactory = new BitosxConnectionFactory(runtimeConnectionString);

        services.AddSingleton(argon2);
        services.AddSingleton(verification);
        services.AddSingleton(outboxCrypto);
        services.AddSingleton(email);
        services.AddSingleton(smtp);
        services.AddSingleton(outbox);
        services.TryAddSingletonTimeProvider();

        // ---- Primitives ----
        services.AddSingleton<IArgon2Core, KonsciousArgon2Core>();
        services.AddSingleton<IAccountPasswordHasher>(sp =>
            new Argon2idPasswordHasher(sp.GetRequiredService<Argon2ParametersOptions>(), sp.GetRequiredService<IArgon2Core>()));
        services.AddSingleton<IEmailVerificationTokenFactory>(sp =>
            new HmacEmailVerificationTokenFactory(sp.GetRequiredService<EmailVerificationSecurityOptions>()));
        services.AddSingleton<IOutboxPayloadProtector>(sp =>
            new AesGcmOutboxPayloadProtector(sp.GetRequiredService<EmailOutboxCryptoOptions>()));
        services.AddSingleton<IVerificationChallengeFactory>(sp =>
            new VerificationChallengeFactory(
                sp.GetRequiredService<IEmailVerificationTokenFactory>(),
                sp.GetRequiredService<IOutboxPayloadProtector>(),
                sp.GetRequiredService<EmailVerificationSecurityOptions>()));
        services.AddSingleton<IVerificationEmailComposer>(sp =>
            new VerificationEmailComposer(sp.GetRequiredService<EmailOptions>()));
        services.AddSingleton<IEmailSender, MailKitGmailEmailSender>();

        // ---- Stores (runtime DML connection) ----
        services.AddSingleton<IAccountRegistrationStore>(_ => new AccountRegistrationStore(connectionFactory));
        services.AddSingleton<IEmailVerificationStore>(_ => new EmailVerificationStore(connectionFactory));
        services.AddSingleton<IEmailOutboxStore>(_ => new EmailOutboxStore(connectionFactory));

        // ---- Services ----
        services.AddScoped<IAccountRegistrationService, AccountRegistrationService>();
        services.AddScoped<IEmailVerificationService, EmailVerificationService>();

        // ---- Background outbox dispatcher ----
        services.AddSingleton<IEmailOutboxDispatcher, EmailOutboxDispatcher>();
        services.AddHostedService<EmailOutboxBackgroundService>();

        return services;
    }

    private static void TryAddSingletonTimeProvider(this IServiceCollection services)
    {
        if (!services.Any(d => d.ServiceType == typeof(TimeProvider)))
        {
            services.AddSingleton(TimeProvider.System);
        }
    }
}
