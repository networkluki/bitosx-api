using System.Reflection;
using BitosX.Application.Security;

namespace BitosX.Application.Tests;

/// <summary>
/// Guards the Phase 2A.1 auth primitives: they live in the Application layer, take NO
/// IdentityModel/JwtBearer dependency (the inward boundary), and carry no vault material.
/// </summary>
public sealed class AuthPrimitivesBoundaryTests
{
    private static readonly Type[] Primitives =
    [
        typeof(IAccessTokenService),
        typeof(AccessToken),
        typeof(JwtOptions),
        typeof(IRefreshTokenFactory),
        typeof(GeneratedRefreshToken),
        typeof(RefreshTokenOptions),
    ];

    [Fact]
    public void AuthPrimitives_LiveInApplicationAssembly()
    {
        foreach (var type in Primitives)
        {
            Assert.Equal("BitosX.Application", type.Assembly.GetName().Name);
        }
    }

    [Fact]
    public void ApplicationAssembly_DoesNotReferenceInfrastructureOnlyDependencies()
    {
        var referenced = typeof(JwtOptions).Assembly.GetReferencedAssemblies()
            .Select(a => a.Name ?? string.Empty)
            .ToArray();

        Assert.DoesNotContain(referenced, n => n.StartsWith("Microsoft.IdentityModel", StringComparison.Ordinal));
        Assert.DoesNotContain(referenced, n => n.Contains("JwtBearer", StringComparison.Ordinal));
        Assert.DoesNotContain(referenced, n => n.Equals("Dapper", StringComparison.Ordinal));
        Assert.DoesNotContain(referenced, n => n.StartsWith("MySqlConnector", StringComparison.Ordinal));
        Assert.DoesNotContain(referenced, n => n.StartsWith("BitosX.Infrastructure", StringComparison.Ordinal));
    }

    [Fact]
    public void SessionServices_HaveNoVaultMembers()
    {
        Type[] sessionTypes =
        [
            typeof(Sessions.LoginCommand), typeof(Sessions.LoginResult),
            typeof(Sessions.RefreshCommand), typeof(Sessions.RefreshResult),
        ];
        foreach (var type in sessionTypes)
        {
            Assert.Equal("BitosX.Application", type.Assembly.GetName().Name);
            foreach (var property in type.GetProperties(BindingFlags.Public | BindingFlags.Instance))
            {
                Assert.DoesNotContain("vault", property.Name, StringComparison.OrdinalIgnoreCase);
                Assert.DoesNotContain("masterpassword", property.Name, StringComparison.OrdinalIgnoreCase);
            }
        }
    }

    [Fact]
    public void AuthPrimitiveMembers_UseNoIdentityModelTypes()
    {
        foreach (var type in Primitives)
        {
            foreach (var property in type.GetProperties(BindingFlags.Public | BindingFlags.Instance))
            {
                AssertNotIdentityModel(property.PropertyType, $"{type.Name}.{property.Name}");
            }

            foreach (var method in type.GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly))
            {
                AssertNotIdentityModel(method.ReturnType, $"{type.Name}.{method.Name} return");
                foreach (var parameter in method.GetParameters())
                {
                    AssertNotIdentityModel(parameter.ParameterType, $"{type.Name}.{method.Name}({parameter.Name})");
                }
            }
        }
    }

    [Fact]
    public void AuthPrimitives_HaveNoVaultMembers()
    {
        foreach (var type in Primitives)
        {
            foreach (var property in type.GetProperties(BindingFlags.Public | BindingFlags.Instance))
            {
                Assert.DoesNotContain("vault", property.Name, StringComparison.OrdinalIgnoreCase);
                Assert.DoesNotContain("masterpassword", property.Name, StringComparison.OrdinalIgnoreCase);
            }
        }
    }

    private static void AssertNotIdentityModel(Type type, string where)
    {
        var ns = type.Namespace ?? string.Empty;
        Assert.False(ns.StartsWith("Microsoft.IdentityModel", StringComparison.Ordinal), $"{where} uses IdentityModel type {type.FullName}");
        Assert.NotEqual("TokenValidationParameters", type.Name);
    }
}
