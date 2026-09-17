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
/// Capability-based composition of the account subsystem. Three independent
/// capabilities are registered separately so that, e.g., login/account-core can
/// run with SMTP delivery disabled:
///   - AccountCore        : DB + password hashing (+ future login/session/JWT)
///   - EmailVerification  : register/verify/resend + outbox persistence (pepper + outbox key)
///   - EmailDelivery      : Gmail SMTP sender + background dispatcher (SMTP credentials)
///
/// Presence vs. malformed: an OPTIONAL capability whose secrets are ABSENT is simply
/// disabled (the API still starts). A capability whose secrets are PRESENT but MALFORMED
/// fails closed at startup (throws) rather than silently disabling itself.
/// </summary>
public static class AccountsServiceCollectionExtensions
{
    public static readonly TimeSpan DeliveryTimeoutSafetyMargin = TimeSpan.FromSeconds(10);

    // ---- Capability detection (once, at composition) ----

    public static AccountCapabilities DetectCapabilities(IConfiguration configuration)
    {
        var accountCore = !string.IsNullOrWhiteSpace(configuration.GetConnectionString("Bitosx"));

        var verification = accountCore
            && !string.IsNullOrWhiteSpace(configuration["Security:EmailVerificationPepper"])
            && !string.IsNullOrWhiteSpace(configuration["Security:EmailOutboxKey"]);

        var delivery = verification
            && !string.IsNullOrWhiteSpace(configuration["Email:SmtpUsername"])
            && !string.IsNullOrWhiteSpace(configuration["Email:SmtpAppPassword"]);

        return new AccountCapabilities
        {
            AccountCoreEnabled = accountCore,
            EmailVerificationEnabled = verification,
            EmailDeliveryEnabled = delivery,
        };
    }

    // ---- AccountCore: DB-backed password hashing (no SMTP dependency) ----

    public static IServiceCollection AddBitosxAccountCore(
        this IServiceCollection services, IConfiguration configuration)
    {
        var argon2 = new Argon2ParametersOptions();
        configuration.GetSection("Security:Argon2").Bind(argon2);

        services.AddSingleton(argon2);
        services.TryAddSingletonTimeProvider();
        services.AddSingleton<IArgon2Core, KonsciousArgon2Core>();
        services.AddSingleton<IAccountPasswordHasher>(sp =>
            new Argon2idPasswordHasher(sp.GetRequiredService<Argon2ParametersOptions>(), sp.GetRequiredService<IArgon2Core>()));
        return services;
    }

    // ---- EmailVerification: register/verify/resend + outbox persistence (no SMTP send) ----

    public static IServiceCollection AddBitosxEmailVerification(
        this IServiceCollection services, IConfiguration configuration, string runtimeConnectionString)
    {
        // Fail closed on malformed verification secrets (present-but-invalid).
        var verification = new EmailVerificationSecurityOptions
        {
            Pepper = configuration["Security:EmailVerificationPepper"]
                     ?? throw new InvalidOperationException("Security:EmailVerificationPepper is required for EmailVerification."),
        };
        var lifetimeSeconds = configuration.GetValue<int?>("Security:EmailVerification:TokenLifetimeSeconds");
        if (lifetimeSeconds is > 0) verification.TokenLifetime = TimeSpan.FromSeconds(lifetimeSeconds.Value);

        var outboxCrypto = new EmailOutboxCryptoOptions { Key = configuration["Security:EmailOutboxKey"] ?? string.Empty };
        var email = new EmailOptions();
        configuration.GetSection("Email").Bind(email);
        var outbox = new EmailOutboxOptions();
        configuration.GetSection("Email:Outbox").Bind(outbox);

        // Construct crypto primitives eagerly so a malformed pepper/outbox key throws NOW.
        var tokenFactory = new HmacEmailVerificationTokenFactory(verification);
        var protector = new AesGcmOutboxPayloadProtector(outboxCrypto);

        var connectionFactory = new BitosxConnectionFactory(runtimeConnectionString);

        services.TryAddSingletonTimeProvider();
        services.AddSingleton(verification);
        services.AddSingleton(email);
        services.AddSingleton(outbox);
        services.AddSingleton<IEmailVerificationTokenFactory>(tokenFactory);
        services.AddSingleton<IOutboxPayloadProtector>(protector);
        services.AddSingleton<IVerificationChallengeFactory>(sp =>
            new VerificationChallengeFactory(tokenFactory, protector, verification));
        services.AddSingleton<IVerificationEmailComposer>(_ => new VerificationEmailComposer(email));

        services.AddSingleton<IAccountRegistrationStore>(_ => new AccountRegistrationStore(connectionFactory));
        services.AddSingleton<IEmailVerificationStore>(sp => new EmailVerificationStore(connectionFactory, sp.GetRequiredService<TimeProvider>()));
        services.AddSingleton<IEmailOutboxStore>(_ => new EmailOutboxStore(connectionFactory));

        services.AddScoped<IAccountRegistrationService, AccountRegistrationService>();
        services.AddScoped<IEmailVerificationService, EmailVerificationService>();
        return services;
    }

    // ---- EmailDelivery: Gmail SMTP sender + background dispatcher (SMTP credentials) ----

    public static IServiceCollection AddBitosxEmailDelivery(
        this IServiceCollection services, IConfiguration configuration)
    {
        var smtp = new SmtpOptions
        {
            Host = configuration["Email:SmtpHost"] ?? "smtp.gmail.com",
            Port = configuration.GetValue("Email:SmtpPort", 587),
            Username = configuration["Email:SmtpUsername"] ?? string.Empty,
            AppPassword = configuration["Email:SmtpAppPassword"] ?? string.Empty,
        };
        var outbox = new EmailOutboxOptions();
        configuration.GetSection("Email:Outbox").Bind(outbox);

        // Fail closed on malformed delivery configuration (present-but-invalid).
        if (smtp.Port != 587) throw new InvalidOperationException("Email:SmtpPort must be 587 (STARTTLS) for EmailDelivery.");
        ValidateDeliveryTimeouts(outbox, smtp);

        services.AddSingleton(smtp);
        services.AddSingleton<ISmtpTransportFactory, MailKitSmtpTransportFactory>();
        services.AddSingleton<IEmailSender, MailKitGmailEmailSender>();
        services.AddSingleton<IEmailRetryBackoff>(_ => new DefaultEmailRetryBackoff(outbox));
        services.AddSingleton<IEmailOutboxDispatcher, EmailOutboxDispatcher>();
        services.AddHostedService<EmailOutboxBackgroundService>();
        return services;
    }

    /// <summary>Enforces LeaseDuration &gt; SMTP AttemptTimeout + margin (fail closed).</summary>
    public static void ValidateDeliveryTimeouts(EmailOutboxOptions outbox, SmtpOptions smtp)
    {
        if (outbox.LeaseDuration <= smtp.AttemptTimeout + DeliveryTimeoutSafetyMargin)
        {
            throw new InvalidOperationException(
                $"Email outbox LeaseDuration ({outbox.LeaseDuration}) must exceed the overall SMTP " +
                $"AttemptTimeout ({smtp.AttemptTimeout}) plus a {DeliveryTimeoutSafetyMargin} safety margin.");
        }
    }

    private static void TryAddSingletonTimeProvider(this IServiceCollection services)
    {
        if (!services.Any(d => d.ServiceType == typeof(TimeProvider)))
        {
            services.AddSingleton(TimeProvider.System);
        }
    }
}
