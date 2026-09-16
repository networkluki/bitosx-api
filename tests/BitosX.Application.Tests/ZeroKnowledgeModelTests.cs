using System.Reflection;
using BitosX.Application.Accounts;
using BitosX.Application.Sessions;
using BitosX.Application.Verification;

namespace BitosX.Application.Tests;

/// <summary>
/// Guards the zero-knowledge boundary and the "no plaintext secrets" rule at
/// the persistence-model level. If a future change adds a forbidden field, one
/// of these tests fails.
/// </summary>
public sealed class ZeroKnowledgeModelTests
{
    private static readonly Type[] PersistenceModels =
    [
        typeof(Account),
        typeof(EmailVerificationChallenge),
        typeof(PhoneVerificationChallenge),
        typeof(Session),
        typeof(RefreshToken),
    ];

    // Names that must never appear on any persistence model.
    private static readonly string[] ForbiddenExactNames =
    [
        "MasterPassword", "VaultPassword", "VaultKey", "VaultSecret", "VaultTotpSecret",
        // plaintext secrets (hashes like PasswordHash / TokenHash / CodeHash are allowed)
        "Password", "PlaintextPassword", "Token", "PlaintextToken", "RefreshToken",
        "Code", "Otp", "PlaintextCode", "PlaintextOtp", "Secret",
    ];

    public static IEnumerable<object[]> Models => PersistenceModels.Select(t => new object[] { t });

    [Theory]
    [MemberData(nameof(Models))]
    public void Model_HasNoVaultOrPlaintextSecretFields(Type model)
    {
        foreach (var property in model.GetProperties(BindingFlags.Public | BindingFlags.Instance))
        {
            var name = property.Name;

            Assert.DoesNotContain("vault", name, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("plaintext", name, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("masterpassword", name, StringComparison.OrdinalIgnoreCase);

            Assert.DoesNotContain(name, ForbiddenExactNames, StringComparer.OrdinalIgnoreCase);
        }
    }

    [Fact]
    public void Account_StoresPasswordOnlyAsHash()
    {
        var names = PropertyNames(typeof(Account));
        Assert.Contains("PasswordHash", names);
        Assert.DoesNotContain("Password", names);
    }

    [Fact]
    public void RefreshToken_StoresTokenOnlyAsHash()
    {
        var names = PropertyNames(typeof(RefreshToken));
        Assert.Contains("TokenHash", names);
        Assert.DoesNotContain("Token", names);
        Assert.DoesNotContain("PlaintextToken", names);
    }

    [Fact]
    public void VerificationChallenges_StoreSecretsOnlyAsHashes()
    {
        Assert.Contains("TokenHash", PropertyNames(typeof(EmailVerificationChallenge)));

        var phone = PropertyNames(typeof(PhoneVerificationChallenge));
        Assert.Contains("CodeHash", phone);
        Assert.DoesNotContain("Code", phone);          // no plaintext OTP
        // Pending phone stays in the challenge until verification succeeds.
        Assert.Contains("PendingPhoneE164", phone);
    }

    private static string[] PropertyNames(Type type)
        => type.GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Select(p => p.Name)
            .ToArray();
}
