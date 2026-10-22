using BitosX.Application.Abstractions.Persistence;
using BitosX.Application.Accounts;
using BitosX.Application.Mfa;
using BitosX.Application.Security;
using Microsoft.Extensions.Time.Testing;

namespace BitosX.Application.Tests;

public sealed class TotpEnrollmentServiceTests
{
    private const string Phc = "$argon2id$v=19$m=8192,t=1,p=1$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYQ";
    private const string Pw = "Correct-Horse-Battery-Staple-1";
    private static readonly DateTime Now = new(2026, 10, 22, 12, 0, 0, DateTimeKind.Utc);
    private static readonly Guid AccountId = Guid.NewGuid();

    private readonly FakeAccountRepository _accounts = new();
    private readonly ConfigurablePasswordHasher _hasher = new();
    private readonly FakeTotpStore _store = new();
    private readonly FakeTotpCrypto _crypto = new();
    private readonly FakeTimeProvider _clock = new(new DateTimeOffset(Now));
    private readonly TotpOptions _options = new();

    private TotpEnrollmentService Service()
        => new(_accounts, _hasher, _store, _crypto, new MfaCodeVerifier(_store, _crypto, _options, _clock), _options, _clock);

    private void SeedAccount() => _accounts.Seed(new Account { Id = AccountId, Email = "User@Example.com", NormalizedEmail = "USER@EXAMPLE.COM", EmailVerifiedAt = Now, PasswordHash = Phc, CreatedAt = Now, UpdatedAt = Now });

    private string CodeFor(byte[] secret) => Rfc6238Totp.Compute(secret, Rfc6238Totp.Step(_clock.GetUtcNow().ToUnixTimeSeconds(), 30), 6);

    [Fact]
    public async Task Begin_CorrectPassword_StoresPendingSecret_ReturnsBase32AndUri()
    {
        SeedAccount();
        var r = await Service().BeginAsync(AccountId, Pw);

        Assert.Equal(TotpBeginOutcome.Started, r.Outcome);
        Assert.Equal(1, _store.StorePendingCalls);
        Assert.True(Base32.TryDecode(r.SecretBase32!, out var secret));
        Assert.Equal(20, secret.Length);
        Assert.Equal(secret, _store.LastPendingSecret!.Ciphertext); // the fake "encrypts" by pass-through
        Assert.StartsWith("otpauth://totp/BitosX:User%40Example.com?secret=" + r.SecretBase32, r.OtpauthUri);
        Assert.Equal("User@Example.com", r.Label);
        Assert.DoesNotContain(r.SecretBase32!, r.ToString());
    }

    [Fact]
    public async Task Begin_WrongPassword_NoSecret()
    {
        SeedAccount();
        _hasher.VerifyResult = PasswordVerificationResult.Failed;
        var r = await Service().BeginAsync(AccountId, Pw);
        Assert.Equal(TotpBeginOutcome.InvalidPassword, r.Outcome);
        Assert.Null(r.SecretBase32);
        Assert.Equal(0, _store.StorePendingCalls);
    }

    [Fact]
    public async Task Begin_AlreadyConfirmed_Refused_WithoutReplacingSecret()
    {
        SeedAccount();
        _store.Enrollment = new TotpEnrollment(AccountId, _crypto.Protect(new byte[20], AccountId), Now, Now, null);
        var r = await Service().BeginAsync(AccountId, Pw);
        Assert.Equal(TotpBeginOutcome.AlreadyEnabled, r.Outcome);
        Assert.Equal(0, _store.StorePendingCalls);
    }

    [Fact]
    public async Task Confirm_ValidCode_IssuesTenRecoveryCodes_WithKeyedVerifiers()
    {
        SeedAccount();
        var secret = new byte[20]; new Random(7).NextBytes(secret);
        _store.Enrollment = new TotpEnrollment(AccountId, _crypto.Protect(secret, AccountId), Now, null, null);

        var r = await Service().ConfirmAsync(AccountId, CodeFor(secret));

        Assert.Equal(TotpConfirmResult.Confirmed, r.Outcome);
        Assert.Equal(10, r.RecoveryCodes.Count);
        Assert.Equal(10, r.RecoveryCodes.Distinct().Count());
        Assert.Equal(Rfc6238Totp.Step(_clock.GetUtcNow().ToUnixTimeSeconds(), 30), _store.LastConfirmedStep);
        Assert.Equal(r.RecoveryCodes.Select(c => _crypto.RecoveryCodeVerifier(RecoveryCodes.Canonicalize(c)!)), _store.LastVerifiers);
        Assert.DoesNotContain(r.RecoveryCodes[0], r.ToString());
    }

    [Fact]
    public async Task Confirm_WrongCode_OrNotPending()
    {
        SeedAccount();
        var secret = new byte[20];
        _store.Enrollment = new TotpEnrollment(AccountId, _crypto.Protect(secret, AccountId), Now, null, null);
        Assert.Equal(TotpConfirmResult.InvalidCode, (await Service().ConfirmAsync(AccountId, "000000")).Outcome);
        Assert.Equal(0, _store.ConfirmCalls);

        _store.Enrollment = null;
        Assert.Equal(TotpConfirmResult.NotPending, (await Service().ConfirmAsync(AccountId, CodeFor(secret))).Outcome);
    }

    [Fact]
    public async Task Disable_RequiresPasswordThenCode_WrongPasswordConsumesNothing()
    {
        SeedAccount();
        var secret = new byte[20];
        _store.Enrollment = new TotpEnrollment(AccountId, _crypto.Protect(secret, AccountId), Now, Now, null);

        _hasher.VerifyResult = PasswordVerificationResult.Failed;
        Assert.Equal(TotpManageOutcome.InvalidCredentials, await Service().DisableAsync(AccountId, "wrong-password-xx", CodeFor(secret)));
        Assert.Equal(0, _store.ConsumeStepCalls);
        Assert.Equal(0, _store.DisableCalls);

        _hasher.VerifyResult = PasswordVerificationResult.Success;
        Assert.Equal(TotpManageOutcome.InvalidCredentials, await Service().DisableAsync(AccountId, Pw, "000000"));
        Assert.Equal(0, _store.DisableCalls);

        Assert.Equal(TotpManageOutcome.Succeeded, await Service().DisableAsync(AccountId, Pw, CodeFor(secret)));
        Assert.Equal(1, _store.DisableCalls);
    }

    [Fact]
    public async Task Disable_WithRecoveryCode_Works_AndNotEnabledIsDistinct()
    {
        SeedAccount();
        _store.Enrollment = new TotpEnrollment(AccountId, _crypto.Protect(new byte[20], AccountId), Now, Now, null);
        Assert.Equal(TotpManageOutcome.Succeeded, await Service().DisableAsync(AccountId, Pw, "abcde-fghjk"));
        Assert.Equal(1, _store.ConsumeRecoveryCalls);

        _store.Enrollment = null;
        Assert.Equal(TotpManageOutcome.NotEnabled, await Service().DisableAsync(AccountId, Pw, "abcde-fghjk"));
        Assert.Equal(1, _hasher.VerifyCalls); // no Argon2 when there is nothing to disable
    }

    [Fact]
    public async Task RegenerateRecoveryCodes_ReplacesSet()
    {
        SeedAccount();
        var secret = new byte[20];
        _store.Enrollment = new TotpEnrollment(AccountId, _crypto.Protect(secret, AccountId), Now, Now, null);
        var r = await Service().RegenerateRecoveryCodesAsync(AccountId, Pw, CodeFor(secret));
        Assert.Equal(TotpManageOutcome.Succeeded, r.Outcome);
        Assert.Equal(10, r.RecoveryCodes.Count);
        Assert.Equal(1, _store.ReplaceCalls);
    }

    [Fact]
    public async Task Status_ReflectsEnrollmentState()
    {
        SeedAccount();
        Assert.Equal(new TotpStatus(false, null, 0, false), await Service().GetStatusAsync(AccountId));
        _store.Enrollment = new TotpEnrollment(AccountId, _crypto.Protect(new byte[20], AccountId), Now, null, null);
        Assert.Equal(new TotpStatus(false, null, 0, true), await Service().GetStatusAsync(AccountId));
        _store.Enrollment = _store.Enrollment with { ConfirmedAt = Now };
        _store.UnusedRecoveryCodes = 7;
        Assert.Equal(new TotpStatus(true, Now, 7, false), await Service().GetStatusAsync(AccountId));
    }
}
