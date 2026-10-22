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
        typeof(MfaChallengeResponse), typeof(TotpLoginRequest), typeof(TotpEnrollRequest), typeof(TotpEnrollResponse),
        typeof(TotpConfirmRequest), typeof(TotpRecoveryCodesResponse), typeof(TotpManageRequest), typeof(TotpStatusResponse),
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

    [Fact]
    public void MfaChallengeResponse_CarriesNoSessionTokens_AndTotpLoginRequest_CarriesNoIdentity()
    {
        var challenge = typeof(MfaChallengeResponse).GetProperties().Select(p => p.Name).ToArray();
        Assert.DoesNotContain(challenge, n => n.Contains("access", StringComparison.OrdinalIgnoreCase) || n.Contains("refresh", StringComparison.OrdinalIgnoreCase));
        var login = typeof(TotpLoginRequest).GetProperties().Select(p => p.Name).OrderBy(n => n).ToArray();
        Assert.Equal(["Code", "MfaToken"], login); // the account is resolved from the challenge, never named by the client
    }

    [Fact]
    public void TotpStatusResponse_CarriesNoSecret()
    {
        var names = typeof(TotpStatusResponse).GetProperties().Select(p => p.Name).ToArray();
        Assert.DoesNotContain(names, n => n.Contains("secret", StringComparison.OrdinalIgnoreCase) || n.Contains("code", StringComparison.OrdinalIgnoreCase) && !n.Contains("Remaining"));
    }
}
