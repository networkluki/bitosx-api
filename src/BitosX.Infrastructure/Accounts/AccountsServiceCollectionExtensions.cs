using BitosX.Application.Abstractions.Persistence;
using BitosX.Application.Accounts;
using BitosX.Application.Email;
using BitosX.Application.Security;
using BitosX.Application.Sessions;
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
        if (!accountCore)
        {
            return AccountCapabilities.None;
        }

        // EmailVerification: the two verification secrets must be set TOGETHER. A partial
        // configuration (exactly one present) is inconsistent → fail closed, never a
        // silent partial-verification capability.
        var pepperSet = !string.IsNullOrWhiteSpace(configuration["Security:EmailVerificationPepper"]);
        var outboxKeySet = !string.IsNullOrWhiteSpace(configuration["Security:EmailOutboxKey"]);
        bool verification;
        if (pepperSet && outboxKeySet)
        {
            verification = true;
        }
        else if (!pepperSet && !outboxKeySet)
        {
            verification = false;
        }
        else
        {
            throw new InvalidOperationException(
                "Partial EmailVerification configuration: Security:EmailVerificationPepper and " +
                "Security:EmailOutboxKey must both be set, or both be absent.");
        }

        // EmailDelivery: presence of the SMTP app password is the explicit "enable delivery"
        // signal. When present, all SMTP configuration must be complete and valid (fail
        // closed) and EmailVerification must be enabled. When absent, delivery is disabled
        // and any remaining non-secret SMTP metadata is harmless.
        var deliveryRequested = !string.IsNullOrWhiteSpace(configuration["Email:SmtpAppPassword"]);
        var delivery = false;
        if (deliveryRequested)
        {
            if (!verification)
            {
                throw new InvalidOperationException(
                    "EmailDelivery requires EmailVerification (Security:EmailVerificationPepper + Security:EmailOutboxKey).");
            }

            ValidateDeliveryConfiguration(configuration); // throws on invalid SMTP config
            delivery = true;
        }

        // Login: an independent AccountCore-backed capability, gated ONLY on the current JWT signing
        // key (Security:JwtSigningKey). No refresh-token secret is involved. Non-secret JWT metadata
        // alone never enables Login. A previous signing secret without a current one is malformed.
        var jwtKeySet = !string.IsNullOrWhiteSpace(configuration["Security:JwtSigningKey"]);
        var previousKeySet = !string.IsNullOrWhiteSpace(configuration["Security:JwtPreviousSigningKey"]);
        bool login;
        if (jwtKeySet)
        {
            _ = BuildValidatedLoginConfiguration(configuration); // fail closed on any invalid login/JWT/refresh config
            login = true;
        }
        else if (previousKeySet)
        {
            throw new InvalidOperationException(
                "Security:JwtPreviousSigningKey is set without Security:JwtSigningKey (orphan previous signing key).");
        }
        else
        {
            login = false;
        }

        return new AccountCapabilities
        {
            AccountCoreEnabled = true,
            EmailVerificationEnabled = verification,
            EmailDeliveryEnabled = delivery,
            LoginEnabled = login,
        };
    }

    // ---- Shared login configuration validation (used by DetectCapabilities AND AddBitosxLogin) ----

    /// <summary>
    /// Binds and fully validates the Login/JWT/refresh configuration, failing closed on any problem.
    /// This is the SINGLE validation path both composition entry points reuse. Returns validated
    /// option objects; never stores secrets in capabilities and never echoes key material in errors.
    /// </summary>
    private static (JwtOptions Jwt, RefreshTokenOptions Refresh) BuildValidatedLoginConfiguration(IConfiguration configuration)
    {
        var jwt = new JwtOptions
        {
            SigningKey = configuration["Security:JwtSigningKey"] ?? string.Empty,
            KeyId = configuration["Security:Jwt:KeyId"] ?? string.Empty,
            PreviousSigningKey = configuration["Security:JwtPreviousSigningKey"],
            PreviousKeyId = configuration["Security:Jwt:PreviousKeyId"],
        };
        if (configuration["Security:Jwt:Issuer"] is { } issuer) jwt.Issuer = issuer;
        if (configuration["Security:Jwt:Audience"] is { } audience) jwt.Audience = audience;

        var lifetimeSeconds = configuration.GetValue<long?>("Security:Jwt:AccessTokenLifetimeSeconds");
        if (lifetimeSeconds is not null)
        {
            if (lifetimeSeconds <= 0) throw new InvalidOperationException("Security:Jwt:AccessTokenLifetimeSeconds must be a positive number of seconds.");
            jwt.AccessTokenLifetime = SecondsToTimeSpan(lifetimeSeconds.Value, "Security:Jwt:AccessTokenLifetimeSeconds");
        }

        var skewSeconds = configuration.GetValue<long?>("Security:Jwt:ClockSkewSeconds");
        if (skewSeconds is not null)
        {
            if (skewSeconds < 0) throw new InvalidOperationException("Security:Jwt:ClockSkewSeconds must be zero or a positive number of seconds.");
            jwt.ClockSkew = SecondsToTimeSpan(skewSeconds.Value, "Security:Jwt:ClockSkewSeconds");
        }

        // Non-key JWT policy (HS256 is fixed in the primitives; issuer/audience/lifetime/skew here).
        if (string.IsNullOrWhiteSpace(jwt.Issuer)) throw new InvalidOperationException("Security:Jwt:Issuer must be non-blank when Login is enabled.");
        if (string.IsNullOrWhiteSpace(jwt.Audience)) throw new InvalidOperationException("Security:Jwt:Audience must be non-blank when Login is enabled.");
        if (jwt.AccessTokenLifetime <= TimeSpan.Zero) throw new InvalidOperationException("Security:Jwt:AccessTokenLifetimeSeconds must be positive.");
        if (jwt.ClockSkew < TimeSpan.Zero) throw new InvalidOperationException("Security:Jwt:ClockSkewSeconds must not be negative.");

        // Key material: current key canonical Base64 >= 32 bytes, mandatory current kid, previous
        // pair both-or-neither, previous key >= 32 bytes. Reuse the single existing key validator.
        _ = JwtKeyMaterial.FromOptions(jwt);

        // Current and previous kid must differ (a shared kid makes verification-key resolution ambiguous).
        if (!string.IsNullOrWhiteSpace(jwt.PreviousKeyId) && string.Equals(jwt.KeyId, jwt.PreviousKeyId, StringComparison.Ordinal))
        {
            throw new InvalidOperationException("Security:Jwt:KeyId and Security:Jwt:PreviousKeyId must differ.");
        }

        // RefreshTokenOptions (no secret; M-2 lifetime validation enforced here at composition).
        var refresh = new RefreshTokenOptions();
        var idleSeconds = configuration.GetValue<long?>("Security:RefreshToken:IdleLifetimeSeconds");
        if (idleSeconds is not null) refresh.IdleLifetime = SecondsToTimeSpan(idleSeconds.Value, "Security:RefreshToken:IdleLifetimeSeconds");
        var absoluteSeconds = configuration.GetValue<long?>("Security:RefreshToken:AbsoluteLifetimeSeconds");
        if (absoluteSeconds is not null) refresh.AbsoluteLifetime = SecondsToTimeSpan(absoluteSeconds.Value, "Security:RefreshToken:AbsoluteLifetimeSeconds");
        ValidateRefreshLifetimes(refresh);

        return (jwt, refresh);
    }

    private static TimeSpan SecondsToTimeSpan(long seconds, string configKey)
    {
        try
        {
            return TimeSpan.FromSeconds(seconds);
        }
        catch (OverflowException)
        {
            throw new InvalidOperationException($"{configKey} is too large to represent.");
        }
        catch (ArgumentException)
        {
            throw new InvalidOperationException($"{configKey} is out of range.");
        }
    }

    /// <summary>
    /// M-2: refresh lifetimes must be positive AND arithmetically safe for the normal session-expiry
    /// calculations (now ± lifetime, last_seen + idle) using one composition-time reference now — so a
    /// malformed/huge lifetime fails at startup, never on a user request.
    /// </summary>
    private static void ValidateRefreshLifetimes(RefreshTokenOptions options)
    {
        if (options.IdleLifetime <= TimeSpan.Zero) throw new InvalidOperationException("Security:RefreshToken:IdleLifetimeSeconds must be positive.");
        if (options.AbsoluteLifetime <= TimeSpan.Zero) throw new InvalidOperationException("Security:RefreshToken:AbsoluteLifetimeSeconds must be positive.");

        var now = DateTime.UtcNow;
        var maxForward = DateTime.MaxValue - now;   // headroom for now + lifetime / last_seen + idle
        var maxBackward = now - DateTime.MinValue;  // headroom for now - idle
        if (options.AbsoluteLifetime > maxForward
            || options.IdleLifetime > maxForward
            || options.IdleLifetime > maxBackward)
        {
            throw new InvalidOperationException("RefreshToken lifetimes are too large to be represented safely in session-expiry calculations.");
        }
    }

    /// <summary>Validates SMTP config when delivery is explicitly enabled (app password present).</summary>
    private static void ValidateDeliveryConfiguration(IConfiguration configuration)
    {
        if (string.IsNullOrWhiteSpace(configuration["Email:SmtpUsername"]))
        {
            throw new InvalidOperationException("EmailDelivery enabled but Email:SmtpUsername is missing.");
        }

        if (string.IsNullOrWhiteSpace(configuration["Email:FromAddress"]))
        {
            throw new InvalidOperationException("EmailDelivery enabled but Email:FromAddress is missing.");
        }

        if (configuration.GetValue("Email:SmtpPort", 587) != 587)
        {
            throw new InvalidOperationException("EmailDelivery enabled but Email:SmtpPort must be 587 (STARTTLS).");
        }

        var outbox = new EmailOutboxOptions();
        configuration.GetSection("Email:Outbox").Bind(outbox);
        var smtp = new SmtpOptions();
        var attemptSeconds = configuration.GetValue<int?>("Email:AttemptTimeoutSeconds");
        if (attemptSeconds is > 0) smtp.AttemptTimeout = TimeSpan.FromSeconds(attemptSeconds.Value);
        ValidateDeliveryTimeouts(outbox, smtp);
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

    // ---- Login: JWT issuance/validation + refresh + session store + login/refresh/session services ----

    /// <summary>
    /// Composes the Login capability: access-JWT issuance, the single validation-parameters source,
    /// SHA-256 refresh-token factory, the session store, and the login/refresh/session-management/
    /// session-authentication application services. Fails closed via the SHARED validation path
    /// (<see cref="BuildValidatedLoginConfiguration"/>) so it can never register a half-working login
    /// stack from malformed/missing JWT or refresh config, even if invoked directly. Does NOT register
    /// SMTP, email verification, JwtBearer, or any HTTP wiring, and opens no DB connection at
    /// registration. Depends on AccountCore (IAccountPasswordHasher) and persistence (IAccountRepository)
    /// being composed alongside it.
    /// </summary>
    public static IServiceCollection AddBitosxLogin(
        this IServiceCollection services, IConfiguration configuration, string runtimeConnectionString)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);
        if (string.IsNullOrWhiteSpace(runtimeConnectionString))
        {
            throw new ArgumentException("A non-blank runtime connection string is required for Login.", nameof(runtimeConnectionString));
        }

        // Fail closed: bind + fully validate JWT/refresh config BEFORE registering anything, using the
        // exact same path DetectCapabilities uses (no drift). Any problem throws here — nothing registered.
        var (jwt, refresh) = BuildValidatedLoginConfiguration(configuration);

        // Construct the connection factory now (no connection is opened until a store method runs).
        var connectionFactory = new BitosxConnectionFactory(runtimeConnectionString);

        services.TryAddSingletonTimeProvider();
        services.AddSingleton(jwt);
        services.AddSingleton(refresh);

        // Crypto / token primitives (Infrastructure): sign with the CURRENT key only, validate CURRENT
        // + PREVIOUS via the single validation-parameters source; SHA-256(raw) refresh verifier.
        services.AddSingleton<IAccessTokenService, JwtAccessTokenService>();
        services.AddSingleton<JwtTokenValidationParametersFactory>();
        services.AddSingleton<IRefreshTokenFactory, Sha256RefreshTokenFactory>();

        // Session store (Dapper/MariaDB) — singleton over the runtime DML connection factory.
        services.AddSingleton<ISessionStore>(sp =>
            new SessionStore(connectionFactory, sp.GetRequiredService<TimeProvider>(), sp.GetRequiredService<RefreshTokenOptions>()));

        // Application orchestration services (per-request).
        services.AddScoped<ILoginService, LoginService>();
        services.AddScoped<IRefreshService, RefreshService>();
        services.AddScoped<ISessionManagementService, SessionManagementService>();
        services.AddScoped<ISessionAuthenticator, SessionAuthenticator>();

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
