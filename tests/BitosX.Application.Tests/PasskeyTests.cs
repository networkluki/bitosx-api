using BitosX.Application.Abstractions.Persistence;
using BitosX.Application.Accounts;
using BitosX.Application.Mfa;
using BitosX.Application.Passkeys;
using BitosX.Application.Security;
using BitosX.Application.Sessions;
using Microsoft.Extensions.Time.Testing;

namespace BitosX.Application.Tests;

/// <summary>In-memory IPasskeyStore fake: only what the TOTP and login paths ask (the count).</summary>
internal sealed class FakePasskeyStore : IPasskeyStore
{
    public int Count { get; set; }

    public int CountCalls { get; private set; }

    public Task<int> CountAsync(Guid accountId, CancellationToken cancellationToken = default) { CountCalls++; return Task.FromResult(Count); }

    public Task<byte[]?> GetOrAssignUserHandleAsync(Guid accountId, byte[] candidate, CancellationToken cancellationToken = default) => throw new NotSupportedException();
    public Task<byte[]?> GetUserHandleAsync(Guid accountId, CancellationToken cancellationToken = default) => throw new NotSupportedException();
    public Task<IReadOnlyList<StoredPasskey>> ListAsync(Guid accountId, CancellationToken cancellationToken = default) => throw new NotSupportedException();
    public Task<StoredPasskey?> FindByCredentialIdAsync(byte[] credentialId, CancellationToken cancellationToken = default) => throw new NotSupportedException();
    public Task<bool> CredentialIdExistsAsync(byte[] credentialId, CancellationToken cancellationToken = default) => throw new NotSupportedException();
    public Task<PasskeyInsertOutcome> InsertAsync(StoredPasskey passkey, int maxPerAccount, CancellationToken cancellationToken = default) => throw new NotSupportedException();
    public Task<bool> RenameAsync(Guid accountId, Guid passkeyId, string name, CancellationToken cancellationToken = default) => throw new NotSupportedException();
    public Task<bool> DeleteAsync(Guid accountId, Guid passkeyId, CancellationToken cancellationToken = default) => throw new NotSupportedException();
    public Task<bool> TryRecordUseAsync(Guid passkeyId, long expectedSignCount, long newSignCount, bool backedUp, DateTime nowUtc, CancellationToken cancellationToken = default) => throw new NotSupportedException();
}

public sealed class WebAuthnOptionsTests
{
    private static WebAuthnOptions Options(string rpId = "vault.bitosx.se", string name = "BitosX", params string[] origins)
        => new() { RelyingPartyId = rpId, RelyingPartyName = name, Origins = origins.Length == 0 ? ["https://vault.bitosx.se"] : origins };

    [Fact]
    public void Shipped_Values_AreValid_InProduction()
    {
        var o = Options();
        o.Validate(allowLocalhost: false);
        Assert.Equal(["https://vault.bitosx.se"], o.Origins);
    }

    [Theory]
    [InlineData("vault.bitosx.se", "https://vault.bitosx.se:443", "https://vault.bitosx.se")]
    [InlineData("bitosx.se", "https://vault.bitosx.se", "https://vault.bitosx.se")]
    [InlineData("bitosx.se", "https://bitosx.se:8443", "https://bitosx.se:8443")]
    public void RegistrableSuffix_AndCanonicalOrigins(string rpId, string origin, string canonical)
    {
        var o = Options(rpId, "BitosX", origin);
        o.Validate(allowLocalhost: false);
        Assert.Equal([canonical], o.Origins);
    }

    [Theory]
    [InlineData("vault.bitosx.se", "http://vault.bitosx.se")]       // http outside Development/Testing
    [InlineData("localhost", "http://localhost:8788")]               // localhost outside Development/Testing
    [InlineData("vault.bitosx.se", "https://evil.example")]          // RP ID does not cover the origin
    [InlineData("vault.bitosx.se", "https://bitosx.se")]             // a parent of the RP ID is not covered
    [InlineData("vault.bitosx.se", "https://xvault.bitosx.se")]      // suffix without a dot boundary
    [InlineData("bitosx.se", "https://vault.bitosx.se/")]            // not an exact origin
    [InlineData("bitosx.se", "https://vault.bitosx.se/path")]
    [InlineData("bitosx.se", "https://user@vault.bitosx.se")]
    [InlineData("bitosx.se", "https://vault.bitosx.se?x=1")]
    [InlineData("bitosx.se", "vault.bitosx.se")]
    [InlineData("se", "https://bitosx.se")]                           // a top-level domain is never registrable
    [InlineData("203.0.113.7", "https://203.0.113.7")]               // IP addresses are not RP IDs
    [InlineData("Vault.BitosX.se", "https://vault.bitosx.se")]       // RP IDs are lower case
    [InlineData("vault.bitosx.se.", "https://vault.bitosx.se")]
    [InlineData("-x.bitosx.se", "https://-x.bitosx.se")]
    [InlineData("app.localhost", "https://app.localhost")]
    public void Invalid_InProduction(string rpId, string origin)
        => Assert.Throws<InvalidOperationException>(() => Options(rpId, "BitosX", origin).Validate(allowLocalhost: false));

    [Fact]
    public void DevelopmentAndTesting_AllowHttpLocalhostOnly()
    {
        Options("localhost", "BitosX", "http://localhost:8788").Validate(allowLocalhost: true);
        Options("localhost", "BitosX", "https://localhost:8443").Validate(allowLocalhost: true);
        Assert.Throws<InvalidOperationException>(() => Options("localhost", "BitosX", "http://127.0.0.1:8788").Validate(allowLocalhost: true));
        Assert.Throws<InvalidOperationException>(() => Options("localhost", "BitosX", "http://[::1]:8788").Validate(allowLocalhost: true));
        Assert.Throws<InvalidOperationException>(() => Options("vault.bitosx.se", "BitosX", "http://vault.bitosx.se").Validate(allowLocalhost: true));
    }

    [Fact]
    public void Incomplete_OrDuplicate_OrTooMany_Refused()
    {
        Assert.False(new WebAuthnOptions().IsConfigured);
        Assert.False(new WebAuthnOptions { Origins = ["", "  "] }.IsConfigured);
        Assert.True(new WebAuthnOptions { RelyingPartyName = "BitosX" }.IsConfigured);
        Assert.Throws<InvalidOperationException>(() => Options("", "BitosX").Validate(false));
        Assert.Throws<InvalidOperationException>(() => Options("vault.bitosx.se", "").Validate(false));
        Assert.Throws<InvalidOperationException>(() => Options("vault.bitosx.se", "Bitos\nX").Validate(false));
        Assert.Throws<InvalidOperationException>(() => new WebAuthnOptions { RelyingPartyId = "vault.bitosx.se", RelyingPartyName = "BitosX" }.Validate(false));
        Assert.Throws<InvalidOperationException>(() => Options("bitosx.se", "BitosX", "https://bitosx.se", "https://bitosx.se:443").Validate(false));
        Assert.Throws<InvalidOperationException>(() => Options("bitosx.se", "BitosX", Enumerable.Range(0, 11).Select(i => $"https://a{i}.bitosx.se").ToArray()).Validate(false));
    }

    [Theory]
    [InlineData("Laptop", "Laptop")]
    [InlineData("  My phone  ", "My phone")]
    [InlineData("👨‍💻 work", "👨‍💻 work")] // emoji with a zero-width joiner is fine
    [InlineData("Ünïcödé", "Ünïcödé")]
    public void NormalizeName_Accepts(string input, string expected) => Assert.Equal(expected, WebAuthnOptions.NormalizeName(input));

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("tab\there")]
    [InlineData("new\nline")]
    [InlineData("nul\0")]
    [InlineData("rtl\u202Eoverride")]
    [InlineData("isolate\u2066x")]
    [InlineData("sep\u2028x")]
    public void NormalizeName_Refuses(string? input) => Assert.Null(WebAuthnOptions.NormalizeName(input));

    [Fact]
    public void NormalizeName_RefusesALoneSurrogate()
    {
        // Built at run time: an attribute argument cannot carry a lone surrogate (metadata stores UTF-8).
        Assert.Null(WebAuthnOptions.NormalizeName("lone" + (char)0xD800 + "surrogate"));
        Assert.Null(WebAuthnOptions.NormalizeName("end" + (char)0xDC00));
    }

    [Fact]
    public void NormalizeName_CountsScalarValues_NotUtf16Units()
    {
        Assert.NotNull(WebAuthnOptions.NormalizeName(string.Concat(Enumerable.Repeat("😀", 64)))); // 128 UTF-16 units, 64 characters
        Assert.Null(WebAuthnOptions.NormalizeName(string.Concat(Enumerable.Repeat("😀", 65))));
        Assert.NotNull(WebAuthnOptions.NormalizeName(new string('a', 64)));
        Assert.Null(WebAuthnOptions.NormalizeName(new string('a', 65)));
    }
}

public sealed class PasskeyTotpInteractionTests
{
    private const string Phc = "$argon2id$v=19$m=8192,t=1,p=1$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYQ";
    private const string Pw = "Correct-Horse-Battery-Staple-1";
    private static readonly DateTime Now = new(2026, 10, 22, 12, 0, 0, DateTimeKind.Utc);
    private static readonly Guid AccountId = Guid.NewGuid();

    [Fact]
    public async Task TotpDisable_WithPasskeys_RefusedBeforePasswordOrCode_StoreRefusalAlsoMapped()
    {
        var accounts = new FakeAccountRepository();
        accounts.Seed(new Account { Id = AccountId, Email = "u@example.com", NormalizedEmail = "U@EXAMPLE.COM", EmailVerifiedAt = Now, PasswordHash = Phc, CreatedAt = Now, UpdatedAt = Now });
        var hasher = new ConfigurablePasswordHasher();
        var store = new FakeTotpStore();
        var crypto = new FakeTotpCrypto();
        var clock = new FakeTimeProvider(new DateTimeOffset(Now));
        var options = new TotpOptions();
        var passkeys = new FakePasskeyStore { Count = 1 };
        store.Enrollment = new TotpEnrollment(AccountId, crypto.Protect(new byte[20], AccountId), Now, Now, null);
        var service = new TotpEnrollmentService(accounts, hasher, store, crypto, new MfaCodeVerifier(store, crypto, options, clock), options, clock, passkeys);

        Assert.Equal(TotpManageOutcome.PasskeysExist, await service.DisableAsync(AccountId, Pw, "abcde-fghjk"));
        Assert.Equal(0, hasher.VerifyCalls);
        Assert.Equal(0, store.ConsumeRecoveryCalls);
        Assert.Equal(0, store.DisableCalls);

        // A passkey added between the check and the store's locked re-check: the store refuses, the outcome says why.
        passkeys.Count = 0;
        store.DisableResult = false;
        Assert.Equal(TotpManageOutcome.PasskeysExist, await service.DisableAsync(AccountId, Pw, "abcde-fghjk"));
        Assert.Equal(1, store.DisableCalls);
    }
}

public sealed class LoginMethodsTests
{
    private const string Phc = "$argon2id$v=19$m=8192,t=1,p=1$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYQ";
    private static readonly DateTime Now = new(2026, 10, 22, 12, 0, 0, DateTimeKind.Utc);

    private static async Task<LoginResult> PasswordStepAsync(IPasskeyStore? passkeys, PasskeyAvailability? availability)
    {
        var accountId = Guid.NewGuid();
        var accounts = new FakeAccountRepository();
        accounts.Seed(new Account { Id = accountId, Email = "u@example.com", NormalizedEmail = "U@EXAMPLE.COM", EmailVerifiedAt = Now, PasswordHash = Phc, CreatedAt = Now, UpdatedAt = Now });
        var totp = new FakeTotpStore
        {
            Enrollment = new TotpEnrollment(accountId, new ProtectedTotpSecret(1, new byte[12], new byte[20], new byte[16]), Now, Now, null),
        };
        var service = new LoginService(accounts, new ConfigurablePasswordHasher(), new FakeRefreshTokenFactory(), new FakeSessionStore(), new FakeAccessTokenService(),
            totp, new FakeMfaChallengeStore(), new TotpOptions(), new SecondFactorAvailability(true), new FakeTimeProvider(new DateTimeOffset(Now)), passkeys, availability);
        return await service.LoginAsync(new LoginCommand("u@example.com", "Correct-Horse-Battery-Staple-1"));
    }

    [Fact]
    public async Task SecondStep_OffersPasskey_OnlyWhenTheServerOffersThem_AndTheAccountHasOne()
    {
        Assert.Equal(["totp", "recovery", "passkey"], (await PasswordStepAsync(new FakePasskeyStore { Count = 2 }, new PasskeyAvailability(true))).MfaMethods);
        Assert.Equal(["totp", "recovery"], (await PasswordStepAsync(new FakePasskeyStore { Count = 0 }, new PasskeyAvailability(true))).MfaMethods);
        Assert.Equal(["totp", "recovery"], (await PasswordStepAsync(new FakePasskeyStore { Count = 2 }, PasskeyAvailability.Off)).MfaMethods);
        Assert.Equal(["totp", "recovery"], (await PasswordStepAsync(null, null)).MfaMethods);
        Assert.Equal(LoginOutcome.MfaRequired, (await PasswordStepAsync(null, null)).Outcome);
    }
}
