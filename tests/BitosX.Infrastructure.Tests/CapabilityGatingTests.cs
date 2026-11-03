using System.Security.Cryptography;
using BitosX.Application.Abstractions.Persistence;
using BitosX.Application.Accounts;
using BitosX.Application.Email;
using BitosX.Application.Security;
using BitosX.Application.Verification;
using BitosX.Infrastructure.Accounts;
using BitosX.Infrastructure.Email;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace BitosX.Infrastructure.Tests;

public sealed class CapabilityGatingTests
{
    private const string DummyConn = "Server=127.0.0.1;Port=3306;Database=bitosx;User ID=x;Password=y;GuidFormat=Char36";
    private static string ValidOutboxKey() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));

    private static IConfiguration Config(bool conn = true, bool verification = true, bool delivery = true, string? outboxKey = null)
    {
        var d = new Dictionary<string, string?>();
        if (conn) d["ConnectionStrings:Bitosx"] = DummyConn;
        if (verification)
        {
            d["Security:EmailVerificationPepper"] = "test-pepper-value-please-long-random";
            d["Security:EmailOutboxKey"] = outboxKey ?? ValidOutboxKey();
        }
        if (delivery)
        {
            d["Email:SmtpUsername"] = "bitosx@example.com";
            d["Email:SmtpAppPassword"] = "app-password";
            d["Email:SmtpPort"] = "587";
        }
        d["Email:FromAddress"] = "bitosx@example.com";
        d["Email:PublicBaseUrl"] = "https://vault.bitosx.se";
        return new ConfigurationBuilder().AddInMemoryCollection(d).Build();
    }

    private static bool Has<T>(IServiceCollection s) => s.Any(x => x.ServiceType == typeof(T));

    // ---- detection ----

    [Fact]
    public void Detect_FullConfig_AllCapabilities()
    {
        var c = AccountsServiceCollectionExtensions.DetectCapabilities(Config());
        Assert.True(c.AccountCoreEnabled);
        Assert.True(c.EmailVerificationEnabled);
        Assert.True(c.EmailDeliveryEnabled);
    }

    [Fact]
    public void Detect_NoSmtp_DeliveryDisabled_CoreAndVerificationEnabled()
    {
        var c = AccountsServiceCollectionExtensions.DetectCapabilities(Config(delivery: false));
        Assert.True(c.AccountCoreEnabled);
        Assert.True(c.EmailVerificationEnabled);
        Assert.False(c.EmailDeliveryEnabled);
    }

    [Fact]
    public void Detect_NoVerificationSecrets_OnlyCore()
    {
        var c = AccountsServiceCollectionExtensions.DetectCapabilities(Config(verification: false, delivery: false));
        Assert.True(c.AccountCoreEnabled);
        Assert.False(c.EmailVerificationEnabled);
        Assert.False(c.EmailDeliveryEnabled);
    }

    [Fact]
    public void Detect_NoConnection_NothingEnabled()
    {
        var c = AccountsServiceCollectionExtensions.DetectCapabilities(Config(conn: false, verification: false, delivery: false));
        Assert.False(c.AccountCoreEnabled);
        Assert.False(c.EmailVerificationEnabled);
        Assert.False(c.EmailDeliveryEnabled);
    }

    private static IConfiguration Raw(Dictionary<string, string?> d)
        => new ConfigurationBuilder().AddInMemoryCollection(d).Build();

    // ---- Email:HoldInOutbox (Development/Testing only) ----

    private static IConfiguration WithHold(IConfiguration baseline)
        => new ConfigurationBuilder().AddConfiguration(baseline)
            .AddInMemoryCollection(new Dictionary<string, string?> { ["Email:HoldInOutbox"] = "true" }).Build();

    [Fact]
    public void Detect_Default_NothingHeld_QueueingFollowsDelivery()
    {
        var withSmtp = AccountsServiceCollectionExtensions.DetectCapabilities(Config(), allowDevelopmentOnlySettings: true);
        Assert.False(withSmtp.EmailHeldInOutbox);
        Assert.True(withSmtp.EmailQueueingEnabled);

        var noSmtp = AccountsServiceCollectionExtensions.DetectCapabilities(Config(delivery: false), allowDevelopmentOnlySettings: true);
        Assert.False(noSmtp.EmailHeldInOutbox);
        Assert.False(noSmtp.EmailQueueingEnabled);
    }

    [Fact]
    public void Detect_HoldInOutbox_WhenAllowed_QueuesWithoutDelivery()
    {
        var c = AccountsServiceCollectionExtensions.DetectCapabilities(WithHold(Config(delivery: false)), allowDevelopmentOnlySettings: true);
        Assert.True(c.EmailVerificationEnabled);
        Assert.False(c.EmailDeliveryEnabled);
        Assert.True(c.EmailHeldInOutbox);
        Assert.True(c.EmailQueueingEnabled);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void Detect_HoldInOutbox_WhenNotAllowed_FailsClosed_EvenWithoutADatabase(bool conn)
    {
        var cfg = WithHold(Config(conn: conn, delivery: false));
        var ex = Assert.Throws<InvalidOperationException>(() => AccountsServiceCollectionExtensions.DetectCapabilities(cfg));
        Assert.Contains("Email:HoldInOutbox", ex.Message, StringComparison.Ordinal);
        // The default (no allowance argument) is the Production behaviour.
        Assert.Throws<InvalidOperationException>(() => AccountsServiceCollectionExtensions.DetectCapabilities(cfg, allowDevelopmentOnlySettings: false));
    }

    [Fact]
    public void Detect_HoldInOutbox_WithDelivery_FailsClosed()
        => Assert.Throws<InvalidOperationException>(
            () => AccountsServiceCollectionExtensions.DetectCapabilities(WithHold(Config()), allowDevelopmentOnlySettings: true));

    [Fact]
    public void Detect_HoldInOutbox_WithoutVerification_FailsClosed()
        => Assert.Throws<InvalidOperationException>(
            () => AccountsServiceCollectionExtensions.DetectCapabilities(WithHold(Config(verification: false, delivery: false)), allowDevelopmentOnlySettings: true));

    [Fact]
    public void Detect_HoldInOutboxFalse_IsTheDefault_AndAcceptedEverywhere()
    {
        var cfg = new ConfigurationBuilder().AddConfiguration(Config(delivery: false))
            .AddInMemoryCollection(new Dictionary<string, string?> { ["Email:HoldInOutbox"] = "false" }).Build();
        Assert.False(AccountsServiceCollectionExtensions.DetectCapabilities(cfg).EmailHeldInOutbox);
    }

    [Fact]
    public void Detect_PartialVerification_PepperOnly_FailsClosed()
    {
        var cfg = Raw(new() { ["ConnectionStrings:Bitosx"] = DummyConn, ["Security:EmailVerificationPepper"] = "p" });
        Assert.Throws<InvalidOperationException>(() => AccountsServiceCollectionExtensions.DetectCapabilities(cfg));
    }

    [Fact]
    public void Detect_PartialVerification_OutboxKeyOnly_FailsClosed()
    {
        var cfg = Raw(new() { ["ConnectionStrings:Bitosx"] = DummyConn, ["Security:EmailOutboxKey"] = ValidOutboxKey() });
        Assert.Throws<InvalidOperationException>(() => AccountsServiceCollectionExtensions.DetectCapabilities(cfg));
    }

    [Fact]
    public void Detect_SmtpMetadataWithoutAppPassword_DeliveryDisabled_NoThrow()
    {
        var cfg = Raw(new()
        {
            ["ConnectionStrings:Bitosx"] = DummyConn,
            ["Security:EmailVerificationPepper"] = "p-long-random",
            ["Security:EmailOutboxKey"] = ValidOutboxKey(),
            ["Email:SmtpUsername"] = "bitosx@example.com",   // harmless metadata
            ["Email:FromAddress"] = "bitosx@example.com",
            ["Email:SmtpHost"] = "smtp.gmail.com",
            ["Email:SmtpPort"] = "587",
            // NO Email:SmtpAppPassword
        });
        var c = AccountsServiceCollectionExtensions.DetectCapabilities(cfg);
        Assert.True(c.EmailVerificationEnabled);
        Assert.False(c.EmailDeliveryEnabled);
    }

    [Fact]
    public void Detect_AppPasswordWithMissingUsername_FailsClosed()
    {
        var cfg = Raw(new()
        {
            ["ConnectionStrings:Bitosx"] = DummyConn,
            ["Security:EmailVerificationPepper"] = "p-long-random",
            ["Security:EmailOutboxKey"] = ValidOutboxKey(),
            ["Email:SmtpAppPassword"] = "app-password",
            ["Email:FromAddress"] = "bitosx@example.com",
            // NO Email:SmtpUsername
        });
        Assert.Throws<InvalidOperationException>(() => AccountsServiceCollectionExtensions.DetectCapabilities(cfg));
    }

    [Fact]
    public void Detect_AppPasswordWithInvalidPort_FailsClosed()
    {
        var cfg = Raw(new()
        {
            ["ConnectionStrings:Bitosx"] = DummyConn,
            ["Security:EmailVerificationPepper"] = "p-long-random",
            ["Security:EmailOutboxKey"] = ValidOutboxKey(),
            ["Email:SmtpAppPassword"] = "app-password",
            ["Email:SmtpUsername"] = "bitosx@example.com",
            ["Email:FromAddress"] = "bitosx@example.com",
            ["Email:SmtpPort"] = "465", // invalid → fail closed
        });
        Assert.Throws<InvalidOperationException>(() => AccountsServiceCollectionExtensions.DetectCapabilities(cfg));
    }

    // ---- composition ----

    [Fact]
    public void AccountCore_InitializesWithoutSmtp()
    {
        var s = new ServiceCollection();
        s.AddBitosxAccountCore(Config(verification: false, delivery: false));
        Assert.True(Has<IAccountPasswordHasher>(s));
        Assert.False(Has<IEmailSender>(s));
        Assert.False(Has<IHostedService>(s));
        Assert.False(Has<IEmailOutboxDispatcher>(s));
    }

    [Fact]
    public void EmailVerification_InitializesWithPepperAndKey_NoSmtp_NoDispatcher()
    {
        var s = new ServiceCollection();
        s.AddBitosxAccountCore(Config(delivery: false));
        s.AddBitosxEmailVerification(Config(delivery: false), DummyConn);
        Assert.True(Has<IEmailVerificationTokenFactory>(s));
        Assert.True(Has<IOutboxPayloadProtector>(s));
        Assert.True(Has<IAccountRegistrationService>(s));
        Assert.True(Has<IEmailVerificationService>(s));
        // Delivery MUST NOT be registered.
        Assert.False(Has<IEmailSender>(s));
        Assert.False(Has<IEmailOutboxDispatcher>(s));
        Assert.False(Has<IHostedService>(s));
    }

    [Fact]
    public void EmailDelivery_RegistersSenderAndDispatcherHostedService()
    {
        var s = new ServiceCollection();
        s.AddBitosxAccountCore(Config());
        s.AddBitosxEmailVerification(Config(), DummyConn);
        s.AddBitosxEmailDelivery(Config());
        Assert.True(Has<IEmailSender>(s));
        Assert.True(Has<IEmailOutboxDispatcher>(s));
        Assert.True(Has<IHostedService>(s)); // EmailOutboxBackgroundService
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("/verify-email")]
    [InlineData("http://vault.bitosx.se")]
    [InlineData("http://localhost:5173")]
    public void EmailVerification_WithoutAnAbsoluteHttpsPublicBaseUrl_FailsClosed(string? url)
    {
        var cfg = new ConfigurationBuilder().AddConfiguration(Config(delivery: false))
            .AddInMemoryCollection(new Dictionary<string, string?> { ["Email:PublicBaseUrl"] = url }).Build();
        var ex = Assert.Throws<InvalidOperationException>(() => new ServiceCollection().AddBitosxEmailVerification(cfg, DummyConn));
        Assert.Contains("Email:PublicBaseUrl", ex.Message);
    }

    [Fact]
    public void EmailVerification_LoopbackHttpPublicBaseUrl_IsAccepted_OnlyWhenTheHostAllowsIt()
    {
        var cfg = new ConfigurationBuilder().AddConfiguration(Config(delivery: false))
            .AddInMemoryCollection(new Dictionary<string, string?> { ["Email:PublicBaseUrl"] = "http://localhost:5173" }).Build();
        new ServiceCollection().AddBitosxEmailVerification(cfg, DummyConn, allowLoopbackHttpBaseUrl: true);
        Assert.Throws<InvalidOperationException>(() => new ServiceCollection().AddBitosxEmailVerification(cfg, DummyConn, allowLoopbackHttpBaseUrl: false));
    }

    [Theory]
    [InlineData("Email:Outbox:PollInterval", "00:00:00")]
    [InlineData("Email:Outbox:BatchSize", "0")]
    [InlineData("Email:Outbox:MaxAttempts", "0")]
    public void OutboxOptions_OutOfRange_FailClosed_InEveryCompositionPath(string key, string value)
    {
        var cfg = new ConfigurationBuilder().AddConfiguration(Config())
            .AddInMemoryCollection(new Dictionary<string, string?> { [key] = value }).Build();
        Assert.Throws<InvalidOperationException>(() => AccountsServiceCollectionExtensions.DetectCapabilities(cfg));
        Assert.Throws<InvalidOperationException>(() => new ServiceCollection().AddBitosxEmailVerification(cfg, DummyConn));
        Assert.Throws<InvalidOperationException>(() => new ServiceCollection().AddBitosxEmailDelivery(cfg));
    }

    [Fact]
    public void EmailDelivery_AppliesTheConfiguredAttemptTimeout()
    {
        var cfg = new ConfigurationBuilder().AddConfiguration(Config())
            .AddInMemoryCollection(new Dictionary<string, string?> { ["Email:AttemptTimeoutSeconds"] = "45" }).Build();
        var s = new ServiceCollection();
        s.AddBitosxEmailDelivery(cfg);
        var smtp = (SmtpOptions)s.Single(d => d.ServiceType == typeof(SmtpOptions)).ImplementationInstance!;
        Assert.Equal(TimeSpan.FromSeconds(45), smtp.AttemptTimeout);
    }

    [Fact]
    public void AccountCore_DerivesTheArgon2MemoryBudget_FromTheAdmissionGatesRealConcurrency()
    {
        var s = new ServiceCollection();
        s.AddBitosxAccountCore(Config());
        var argon2 = (Argon2ParametersOptions)s.Single(d => d.ServiceType == typeof(Argon2ParametersOptions)).ImplementationInstance!;
        Assert.Equal(2, argon2.MaxConcurrency); // the gate runs 2 hashes at once by default
        Assert.Equal(Argon2ParametersOptions.MemoryBudgetKiB / 2, argon2.EffectiveMaxVerifyMemoryKiB());
    }

    [Fact]
    public void EmailVerification_MalformedOutboxKey_FailsClosed()
    {
        var s = new ServiceCollection();
        // present-but-invalid key (not base64 / not 32 bytes) → throw at composition.
        Assert.ThrowsAny<Exception>(() => s.AddBitosxEmailVerification(Config(outboxKey: "not-a-valid-key"), DummyConn));
    }

    [Fact]
    public void EmailDelivery_InvalidPort_FailsClosed()
    {
        var d = new Dictionary<string, string?>
        {
            ["ConnectionStrings:Bitosx"] = DummyConn,
            ["Email:SmtpUsername"] = "bitosx@example.com",
            ["Email:SmtpAppPassword"] = "app-password",
            ["Email:SmtpPort"] = "465", // not 587 → fail closed
        };
        var cfg = new ConfigurationBuilder().AddInMemoryCollection(d).Build();
        Assert.Throws<InvalidOperationException>(() => new ServiceCollection().AddBitosxEmailDelivery(cfg));
    }
}
