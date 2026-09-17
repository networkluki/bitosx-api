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
