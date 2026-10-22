using System.Reflection;
using BitosX.Contracts.Accounts;

namespace BitosX.Application.Tests;

/// <summary>Guards that public API contracts never expose secret-bearing fields.</summary>
public sealed class AuthContractsSecurityTests
{
    private static readonly Type[] Contracts =
    [
        typeof(RegisterRequest), typeof(VerifyEmailRequest),
        typeof(ResendVerificationRequest), typeof(AcceptedResponse),
        typeof(ForgotPasswordRequest), typeof(ResetPasswordRequest), typeof(DeleteAccountRequest),
    ];

    [Fact]
    public void Contracts_ExposeNoHashOrVerifierFields()
    {
        foreach (var t in Contracts)
        {
            foreach (var p in t.GetProperties(BindingFlags.Public | BindingFlags.Instance))
            {
                Assert.DoesNotContain("hash", p.Name, StringComparison.OrdinalIgnoreCase);
                Assert.DoesNotContain("verifier", p.Name, StringComparison.OrdinalIgnoreCase);
                Assert.DoesNotContain("pepper", p.Name, StringComparison.OrdinalIgnoreCase);
            }
        }
    }

    [Fact]
    public void RegisterRequest_IsEmailOnly_NoPassword()
    {
        var names = typeof(RegisterRequest).GetProperties().Select(p => p.Name).ToArray();
        Assert.Contains("Email", names);
        Assert.DoesNotContain(names, n => n.Contains("password", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void AcceptedResponse_CarriesNoSecretsOrTokens()
    {
        var names = typeof(AcceptedResponse).GetProperties().Select(p => p.Name).ToArray();
        Assert.DoesNotContain(names, n => n.Contains("password", StringComparison.OrdinalIgnoreCase)
            || n.Contains("token", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void ForgotPasswordRequest_IsEmailOnly()
    {
        var names = typeof(ForgotPasswordRequest).GetProperties().Select(p => p.Name).ToArray();
        Assert.Equal(["Email"], names);
    }

    [Fact]
    public void DeleteAccountRequest_CarriesNoIdentity_OnlyPassword()
    {
        // The account to delete is always the authenticated caller's; the body must not be able to name another.
        var names = typeof(DeleteAccountRequest).GetProperties().Select(p => p.Name).ToArray();
        Assert.Equal(["Password"], names);
    }
}
