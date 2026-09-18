using BitosX.Api.Security;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace BitosX.Api.Tests;

/// <summary>
/// Unit tests for fail-closed configuration validation of Security:PublicExposureHardening. Invalid or
/// out-of-range values throw at registration (which fails startup); valid config binds cleanly.
/// </summary>
public sealed class PublicExposureHardeningConfigTests
{
    private static IConfiguration Cfg(Dictionary<string, string?> d) => new ConfigurationBuilder().AddInMemoryCollection(d).Build();

    private static void Add(Dictionary<string, string?> d) => new ServiceCollection().AddPublicExposureHardening(Cfg(d));

    private const string P = "Security:PublicExposureHardening:";

    [Fact]
    public void Defaults_AreValid_EnabledFalse()
    {
        var services = new ServiceCollection();
        services.AddPublicExposureHardening(Cfg(new Dictionary<string, string?>()));
        var options = services.BuildServiceProvider().GetRequiredService<PublicExposureHardeningOptions>();

        Assert.False(options.Enabled);
        Assert.Equal(10, options.LoginPerIp.TokenLimit);
        Assert.Equal(5, options.LoginPerEmail.TokenLimit);
        Assert.Equal(30, options.RefreshPerIp.TokenLimit);
        Assert.Equal(4096, options.PartitionState.MaxIpPartitions);
    }

    [Fact]
    public void EnabledTrue_ValidConfig_Binds()
    {
        var services = new ServiceCollection();
        services.AddPublicExposureHardening(Cfg(new Dictionary<string, string?> { [P + "Enabled"] = "true" }));
        var sp = services.BuildServiceProvider();
        Assert.True(sp.GetRequiredService<PublicExposureHardeningOptions>().Enabled);
        Assert.NotNull(sp.GetRequiredService<AuthRateLimiters>());
    }

    [Fact] public void ZeroTokenLimit_Throws() => Assert.Throws<InvalidOperationException>(() => Add(new() { [P + "LoginPerIp:TokenLimit"] = "0" }));
    [Fact] public void NegativeReplenishment_Throws() => Assert.Throws<InvalidOperationException>(() => Add(new() { [P + "LoginPerIp:ReplenishmentSeconds"] = "-1" }));
    [Fact] public void TokensPerPeriodExceedsLimit_Throws() => Assert.Throws<InvalidOperationException>(() => Add(new() { [P + "LoginPerEmail:TokensPerPeriod"] = "999" }));
    [Fact] public void ZeroMaxIpPartitions_Throws() => Assert.Throws<InvalidOperationException>(() => Add(new() { [P + "PartitionState:MaxIpPartitions"] = "0" }));
    [Fact] public void ZeroIdleExpiration_Throws() => Assert.Throws<InvalidOperationException>(() => Add(new() { [P + "PartitionState:IdleExpirationMinutes"] = "0" }));

    // Invalid config fails startup even when disabled (no silently-repaired security config).
    [Fact] public void InvalidConfig_FailsEvenWhenDisabled() => Assert.Throws<InvalidOperationException>(() => Add(new() { [P + "Enabled"] = "false", [P + "RefreshPerIp:TokenLimit"] = "-5" }));

    // ---- 2D.2 additions ----

    [Fact]
    public void GlobalLoginBudget_And_Jitter_Defaults_AreValid()
    {
        var services = new ServiceCollection();
        services.AddPublicExposureHardening(Cfg(new Dictionary<string, string?>()));
        var o = services.BuildServiceProvider().GetRequiredService<PublicExposureHardeningOptions>();
        Assert.Equal(30, o.GlobalLoginBudget.TokenLimit);
        Assert.Equal(15, o.GlobalLoginBudget.TokensPerPeriod);
        Assert.Equal(25, o.LoginJitter.MinMilliseconds);
        Assert.Equal(75, o.LoginJitter.MaxMilliseconds);
    }

    [Fact] public void GlobalBudget_ZeroTokenLimit_Throws() => Assert.Throws<InvalidOperationException>(() => Add(new() { [P + "GlobalLoginBudget:TokenLimit"] = "0" }));
    [Fact] public void GlobalBudget_TokensPerPeriodExceedsLimit_Throws() => Assert.Throws<InvalidOperationException>(() => Add(new() { [P + "GlobalLoginBudget:TokensPerPeriod"] = "999" }));
    [Fact] public void GlobalBudget_ZeroReplenishment_Throws() => Assert.Throws<InvalidOperationException>(() => Add(new() { [P + "GlobalLoginBudget:ReplenishmentSeconds"] = "0" }));
    [Fact] public void Jitter_NegativeMin_Throws() => Assert.Throws<InvalidOperationException>(() => Add(new() { [P + "LoginJitter:MinMilliseconds"] = "-1" }));
    [Fact] public void Jitter_MaxBelowMin_Throws() => Assert.Throws<InvalidOperationException>(() => Add(new() { [P + "LoginJitter:MinMilliseconds"] = "75", [P + "LoginJitter:MaxMilliseconds"] = "25" }));
}
