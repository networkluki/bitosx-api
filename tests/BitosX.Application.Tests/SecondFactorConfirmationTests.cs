using BitosX.Application.Abstractions.Persistence;
using BitosX.Application.Mfa;
using Microsoft.Extensions.Time.Testing;

namespace BitosX.Application.Tests;

public sealed class SecondFactorConfirmationTests
{
    private static readonly DateTime Now = new(2026, 11, 1, 12, 0, 0, DateTimeKind.Utc);
    private static readonly Guid AccountId = Guid.NewGuid();
    private static readonly byte[] Secret = Enumerable.Range(1, 20).Select(i => (byte)i).ToArray();

    private readonly FakeTotpStore _store = new();
    private readonly FakeTotpCrypto _crypto = new();
    private readonly FakeTimeProvider _clock = new(new DateTimeOffset(Now));
    private readonly TotpOptions _options = new();

    private SecondFactorConfirmation Service(bool verifier = true)
        => new(_store, verifier ? new MfaCodeVerifier(_store, _crypto, _options, _clock) : null);

    private void Confirmed() => _store.Enrollment = new TotpEnrollment(AccountId, _crypto.Protect(Secret, AccountId), Now, Now, null);

    private string CurrentCode() => Rfc6238Totp.Compute(Secret, Rfc6238Totp.Step(_clock.GetUtcNow().ToUnixTimeSeconds(), 30), 6);

    [Fact]
    public async Task NoEnrollment_OrPendingOnly_IsNotRequired()
    {
        Assert.Equal(SecondFactorCheck.NotRequired, await Service().CheckAsync(AccountId, null));
        _store.Enrollment = new TotpEnrollment(AccountId, _crypto.Protect(Secret, AccountId), Now, null, null);
        Assert.Equal(SecondFactorCheck.NotRequired, await Service().CheckAsync(AccountId, null));
        Assert.Equal(SecondFactorCheck.NotRequired, await Service(verifier: false).CheckAsync(AccountId, null));
    }

    [Fact]
    public async Task Confirmed_ValidTotp_IsAccepted_AndConsumesTheStep()
    {
        Confirmed();
        Assert.Equal(SecondFactorCheck.Accepted, await Service().CheckAsync(AccountId, CurrentCode()));
        Assert.Equal(1, _store.ConsumeStepCalls);
    }

    [Fact]
    public async Task Confirmed_ValidRecoveryCode_IsAccepted()
    {
        Confirmed();
        Assert.Equal(SecondFactorCheck.Accepted, await Service().CheckAsync(AccountId, "abcde-fghjk"));
        Assert.Equal(1, _store.ConsumeRecoveryCalls);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("000000")]
    [InlineData("not-a-code")]
    public async Task Confirmed_MissingOrWrongCode_IsRejected(string? code)
    {
        Confirmed();
        _store.ConsumeRecoveryResult = false;
        Assert.Equal(SecondFactorCheck.Rejected, await Service().CheckAsync(AccountId, code));
    }

    [Fact]
    public async Task Confirmed_WithoutTheTotpCapability_IsUnavailable_NeverAccepted()
    {
        Confirmed();
        Assert.Equal(SecondFactorCheck.Unavailable, await Service(verifier: false).CheckAsync(AccountId, CurrentCode()));
    }
}
