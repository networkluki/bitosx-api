using BitosX.Application.Abstractions.Persistence;
using BitosX.Application.Email;
using BitosX.Application.Security;
using BitosX.Application.Sessions;
using BitosX.Infrastructure.Accounts;
using BitosX.Infrastructure.Persistence;
using BitosX.Infrastructure.Security;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;

namespace BitosX.Infrastructure.Tests;

/// <summary>Composition tests for AddBitosxLogin: registrations, fail-closed direct calls, secret-safe options.</summary>
public sealed class AddBitosxLoginTests
{
    private const string Conn = "Server=127.0.0.1;Port=3306;Database=bitosx;User ID=x;Password=y;GuidFormat=Char36";

    private static string Key32(byte seed) => Convert.ToBase64String(Enumerable.Repeat(seed, 32).ToArray());

    private static Dictionary<string, string?> ValidLogin() => new()
    {
        ["ConnectionStrings:Bitosx"] = Conn,
        ["Security:JwtSigningKey"] = Key32(0x11),
        ["Security:Jwt:KeyId"] = "k1",
    };

    private static IConfiguration Cfg(Dictionary<string, string?> d) => new ConfigurationBuilder().AddInMemoryCollection(d).Build();

    private static ServiceProvider BuildProvider(Dictionary<string, string?> d)
    {
        var services = new ServiceCollection();
        var cfg = Cfg(d);
        services.AddBitosxPersistence(Conn);   // IAccountRepository (no migrator)
        services.AddBitosxAccountCore(cfg);    // IAccountPasswordHasher
        services.AddBitosxLogin(cfg, Conn);    // login graph
        return services.BuildServiceProvider();
    }

    // ---- registrations ----

    [Fact]
    public void Registers_AllLoginServices_WithCorrectConcreteTypes()
    {
        using var sp = BuildProvider(ValidLogin());
        using var scope = sp.CreateScope();
        var p = scope.ServiceProvider;

        Assert.IsType<JwtAccessTokenService>(p.GetRequiredService<IAccessTokenService>());
        Assert.NotNull(p.GetRequiredService<JwtTokenValidationParametersFactory>());
        Assert.IsType<Sha256RefreshTokenFactory>(p.GetRequiredService<IRefreshTokenFactory>());
        Assert.IsType<SessionStore>(p.GetRequiredService<ISessionStore>());
        Assert.IsType<LoginService>(p.GetRequiredService<ILoginService>());
        Assert.IsType<RefreshService>(p.GetRequiredService<IRefreshService>());
        Assert.IsType<SessionManagementService>(p.GetRequiredService<ISessionManagementService>());
        Assert.IsType<SessionAuthenticator>(p.GetRequiredService<ISessionAuthenticator>());
    }

    [Fact]
    public void Composition_RequiresNoSmtp()
    {
        using var sp = BuildProvider(ValidLogin());
        Assert.Null(sp.GetService<IEmailSender>());
        Assert.Empty(sp.GetServices<Microsoft.Extensions.Hosting.IHostedService>());
    }

    [Fact]
    public async Task Composition_IssuesWithCurrentKid_AndFactoryValidatesIssuedToken()
    {
        var d = ValidLogin();
        d["Security:JwtPreviousSigningKey"] = Key32(0x22);
        d["Security:Jwt:PreviousKeyId"] = "k0";
        using var sp = BuildProvider(d);
        using var scope = sp.CreateScope();
        var p = scope.ServiceProvider;

        var issued = p.GetRequiredService<IAccessTokenService>().Issue(Guid.NewGuid(), Guid.NewGuid(), DateTime.UtcNow);
        var jwt = new JsonWebTokenHandler().ReadJsonWebToken(issued.Token);
        Assert.Equal("k1", jwt.Kid); // signs with CURRENT kid only

        var parameters = p.GetRequiredService<JwtTokenValidationParametersFactory>().Create();
        var result = await new JsonWebTokenHandler().ValidateTokenAsync(issued.Token, parameters);
        Assert.True(result.IsValid);
    }

    // ---- fail-closed direct calls (no half-configured stack) ----

    private static void AssertDirectThrows(Dictionary<string, string?> d)
        => Assert.Throws<InvalidOperationException>(() => new ServiceCollection().AddBitosxLogin(Cfg(d), Conn));

    [Fact] public void Direct_MissingCurrentKey_Throws() { var d = ValidLogin(); d.Remove("Security:JwtSigningKey"); AssertDirectThrows(d); }
    [Fact] public void Direct_MissingKid_Throws() { var d = ValidLogin(); d.Remove("Security:Jwt:KeyId"); AssertDirectThrows(d); }
    [Fact] public void Direct_BadKey_Throws() { var d = ValidLogin(); d["Security:JwtSigningKey"] = "!!!"; AssertDirectThrows(d); }
    [Fact] public void Direct_PartialPreviousPair_Throws() { var d = ValidLogin(); d["Security:JwtPreviousSigningKey"] = Key32(0x22); AssertDirectThrows(d); }
    [Fact] public void Direct_InvalidRefreshLifetime_Throws() { var d = ValidLogin(); d["Security:RefreshToken:IdleLifetimeSeconds"] = "0"; AssertDirectThrows(d); }

    [Fact]
    public void Direct_BlankRuntimeConnectionString_Throws()
        => Assert.Throws<ArgumentException>(() => new ServiceCollection().AddBitosxLogin(Cfg(ValidLogin()), "  "));

    // ---- secret-safe options ----

    [Fact]
    public void JwtOptions_ToString_DoesNotExposeSigningKey()
    {
        using var sp = BuildProvider(ValidLogin());
        var options = sp.GetRequiredService<JwtOptions>();
        Assert.DoesNotContain(Key32(0x11), options.ToString(), StringComparison.Ordinal);
    }
}
