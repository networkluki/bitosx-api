using System.Security.Cryptography;
using BitosX.Application.Abstractions.Persistence;
using BitosX.Application.Housekeeping;
using BitosX.Application.Mfa;
using BitosX.Application.Security;
using BitosX.Infrastructure.Housekeeping;
using BitosX.Infrastructure.Persistence;
using Dapper;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;

namespace BitosX.Infrastructure.Tests;

/// <summary>
/// Migration 0009 and the passkey stores, run with the DML-only runtime account (as the web host): the user handle,
/// insert rules under the TOTP lock (TOTP required, per-account maximum, unique credential id), TOTP disable refused
/// while passkeys exist, the counter compare-and-set, and single-use, purpose-bound ceremonies.
/// </summary>
[Collection("Persistence")]
public sealed class PasskeyStoreTests
{
    private readonly DatabaseFixture _fixture;
    private readonly AccountsTestContext _ctx;
    private readonly PasskeyStore _passkeys;
    private readonly WebAuthnChallengeStore _ceremonies;
    private readonly TotpStore _totp;
    private readonly MfaChallengeStore _mfa;

    public PasskeyStoreTests(DatabaseFixture fixture)
    {
        _fixture = fixture;
        _ctx = new AccountsTestContext(fixture.ConnectionFactory);
        _passkeys = new PasskeyStore(fixture.RuntimeConnectionFactory);
        _ceremonies = new WebAuthnChallengeStore(fixture.RuntimeConnectionFactory);
        _totp = new TotpStore(fixture.RuntimeConnectionFactory);
        _mfa = new MfaChallengeStore(fixture.RuntimeConnectionFactory);
    }

    private async Task<long> CountAsync(string sql, object p)
    {
        await using var c = await _fixture.ConnectionFactory.OpenConnectionAsync();
        return await c.ExecuteScalarAsync<long>(new CommandDefinition(sql, p));
    }

    private async Task<Guid> AccountWithTotpAsync(DateTime now, bool confirm = true)
    {
        var a = (await _ctx.RegisterAsync(now)).AccountId;
        var secret = new ProtectedTotpSecret(1, RandomNumberGenerator.GetBytes(12), RandomNumberGenerator.GetBytes(20), RandomNumberGenerator.GetBytes(16));
        Assert.Equal(TotpPendingOutcome.Stored, await _totp.StorePendingAsync(a, secret, now));
        if (confirm)
        {
            Assert.Equal(TotpConfirmOutcome.Confirmed, await _totp.ConfirmAsync(a, secret.Nonce, 100, [RandomNumberGenerator.GetBytes(32)], now));
        }

        return a;
    }

    private static StoredPasskey Passkey(Guid accountId, byte[] userHandle, DateTime now, byte[]? credentialId = null, string name = "Laptop")
        => new(Guid.NewGuid(), accountId, credentialId ?? RandomNumberGenerator.GetBytes(64), RandomNumberGenerator.GetBytes(77), 0, userHandle, name,
            Guid.Parse("01020304-0506-0708-090a-0b0c0d0e0f10"), true, false, "internal,hybrid", now, null);

    [Fact]
    public async Task Migration0009_IsApplied_WithItsConstraints()
    {
        Assert.Contains("0009_webauthn_passkeys.sql", await _fixture.GetRecordedMigrationsAsync());
        Assert.Contains("0009_webauthn_passkeys.sql", SqlMigrationRunner.KnownMigrations());

        await _fixture.ResetAsync();
        var now = AccountsTestContext.NowMicro();
        await using var c = await _fixture.RuntimeConnectionFactory.OpenConnectionAsync();
        // The purpose is one of the three.
        await Assert.ThrowsAnyAsync<Exception>(() => c.ExecuteAsync(
            "INSERT INTO webauthn_challenges (id, purpose, handle_hash, challenge, created_at, expires_at) VALUES (UUID(), 'other', RANDOM_BYTES(32), RANDOM_BYTES(32), @now, @now)", new { now }));
        // A credential needs an existing account (the store refuses it; the FK would too).
        Assert.Equal(PasskeyInsertOutcome.TwoFactorRequired, await _passkeys.InsertAsync(Passkey(Guid.NewGuid(), new byte[32], now), 10));
        await Assert.ThrowsAnyAsync<Exception>(() => c.ExecuteAsync(
            """
            INSERT INTO webauthn_credentials (id, account_id, credential_id, public_key, sign_count, user_handle, name, aaguid, backup_eligible, backed_up, created_at)
            VALUES (UUID(), UUID(), RANDOM_BYTES(16), RANDOM_BYTES(16), 0, RANDOM_BYTES(32), 'x', RANDOM_BYTES(16), 0, 0, @now)
            """, new { now }));
    }

    [Fact]
    public async Task UserHandle_AssignedOnce_Random_UniquePerAccount()
    {
        await _fixture.ResetAsync();
        var now = AccountsTestContext.NowMicro();
        var a = (await _ctx.RegisterAsync(now)).AccountId;
        var b = (await _ctx.RegisterAsync(now)).AccountId;

        Assert.Null(await _passkeys.GetUserHandleAsync(a));
        var first = RandomNumberGenerator.GetBytes(32);
        Assert.Equal(first, await _passkeys.GetOrAssignUserHandleAsync(a, first));
        Assert.Equal(first, await _passkeys.GetOrAssignUserHandleAsync(a, RandomNumberGenerator.GetBytes(32))); // kept
        Assert.Equal(first, await _passkeys.GetUserHandleAsync(a));
        Assert.Null(await _passkeys.GetOrAssignUserHandleAsync(Guid.NewGuid(), RandomNumberGenerator.GetBytes(32)));

        // The unique key refuses the same handle for a second account.
        await Assert.ThrowsAnyAsync<Exception>(() => _passkeys.GetOrAssignUserHandleAsync(b, first));
        await Assert.ThrowsAsync<ArgumentException>(() => _passkeys.GetOrAssignUserHandleAsync(b, new byte[16]));
    }

    [Fact]
    public async Task Insert_NeedsConfirmedTotp_RespectsTheMaximum_RefusesDuplicates_RoundTrips()
    {
        await _fixture.ResetAsync();
        var now = AccountsTestContext.NowMicro();
        var noTotp = (await _ctx.RegisterAsync(now)).AccountId;
        var pending = await AccountWithTotpAsync(now, confirm: false);
        var a = await AccountWithTotpAsync(now);
        var handle = RandomNumberGenerator.GetBytes(32);

        Assert.Equal(PasskeyInsertOutcome.TwoFactorRequired, await _passkeys.InsertAsync(Passkey(noTotp, handle, now), 10));
        Assert.Equal(PasskeyInsertOutcome.TwoFactorRequired, await _passkeys.InsertAsync(Passkey(pending, handle, now), 10));

        var first = Passkey(a, handle, now, name: "Lap 💻");
        Assert.Equal(PasskeyInsertOutcome.Inserted, await _passkeys.InsertAsync(first, 2));
        Assert.Equal(PasskeyInsertOutcome.DuplicateCredential, await _passkeys.InsertAsync(Passkey(a, handle, now, first.CredentialId), 2));
        var second = Passkey(a, handle, now.AddSeconds(1));
        Assert.Equal(PasskeyInsertOutcome.Inserted, await _passkeys.InsertAsync(second, 2));
        Assert.Equal(PasskeyInsertOutcome.LimitReached, await _passkeys.InsertAsync(Passkey(a, handle, now), 2));

        Assert.Equal(2, await _passkeys.CountAsync(a));
        var list = await _passkeys.ListAsync(a);
        Assert.Equal([first.Id, second.Id], list.Select(p => p.Id).ToArray());
        var read = await _passkeys.FindByCredentialIdAsync(first.CredentialId);
        Assert.NotNull(read);
        Assert.Equal(first with { }, read! with { CredentialId = first.CredentialId, PublicKey = first.PublicKey, UserHandle = first.UserHandle });
        Assert.Equal(first.PublicKey, read.PublicKey);
        Assert.Equal(first.UserHandle, read.UserHandle);
        Assert.Equal(DateTimeKind.Utc, read.CreatedAt.Kind);
        Assert.Equal("01020304-0506-0708-090a-0b0c0d0e0f10", read.AaGuid.ToString());
        Assert.Equal("0102030405060708090A0B0C0D0E0F10", Convert.ToHexString(await ScalarBytesAsync("SELECT aaguid FROM webauthn_credentials WHERE id = @id", first.Id)));
        Assert.True(await _passkeys.CredentialIdExistsAsync(first.CredentialId));
        Assert.Null(await _passkeys.FindByCredentialIdAsync(RandomNumberGenerator.GetBytes(64)));
        Assert.Null(await _passkeys.FindByCredentialIdAsync([]));
    }

    private async Task<byte[]> ScalarBytesAsync(string sql, Guid id)
    {
        await using var c = await _fixture.ConnectionFactory.OpenConnectionAsync();
        return (await c.ExecuteScalarAsync<byte[]>(new CommandDefinition(sql, new { id })))!;
    }

    [Fact]
    public async Task ConcurrentRegistrations_NeverExceedTheMaximum()
    {
        await _fixture.ResetAsync();
        var now = AccountsTestContext.NowMicro();
        var a = await AccountWithTotpAsync(now);
        var handle = RandomNumberGenerator.GetBytes(32);

        var outcomes = await Task.WhenAll(Enumerable.Range(0, 14).Select(_ => Task.Run(() => _passkeys.InsertAsync(Passkey(a, handle, now), 10))));
        Assert.Equal(10, outcomes.Count(o => o == PasskeyInsertOutcome.Inserted));
        Assert.Equal(4, outcomes.Count(o => o == PasskeyInsertOutcome.LimitReached));
        Assert.Equal(10, await _passkeys.CountAsync(a));
    }

    [Fact]
    public async Task TotpDisable_RefusedWhilePasskeysExist_AndRacesResolveToOneConsistentState()
    {
        await _fixture.ResetAsync();
        var now = AccountsTestContext.NowMicro();
        var a = await AccountWithTotpAsync(now);
        var handle = RandomNumberGenerator.GetBytes(32);
        var passkey = Passkey(a, handle, now);
        Assert.Equal(PasskeyInsertOutcome.Inserted, await _passkeys.InsertAsync(passkey, 10));

        Assert.False(await _totp.DisableAsync(a));
        Assert.True((await _totp.GetAsync(a))!.IsConfirmed);
        Assert.True(await _passkeys.DeleteAsync(a, passkey.Id));
        Assert.True(await _totp.DisableAsync(a));
        Assert.Null(await _totp.GetAsync(a));

        // Disable racing a registration: never both "TOTP gone" and "a passkey exists".
        for (var i = 0; i < 10; i++)
        {
            var b = await AccountWithTotpAsync(now);
            var insert = Task.Run(() => _passkeys.InsertAsync(Passkey(b, RandomNumberGenerator.GetBytes(32), now), 10));
            var disable = Task.Run(() => _totp.DisableAsync(b));
            var inserted = await insert;
            var disabled = await disable;
            var totpGone = await _totp.GetAsync(b) is null;
            var passkeys = await _passkeys.CountAsync(b);
            Assert.True(totpGone ^ (passkeys == 1), $"inserted={inserted} disabled={disabled}");
            Assert.Equal(inserted == PasskeyInsertOutcome.Inserted, !disabled);
        }
    }

    [Fact]
    public async Task RecordUse_IsACompareAndSetOnTheCounter_RenameAndDelete_AreAccountScoped()
    {
        await _fixture.ResetAsync();
        var now = AccountsTestContext.NowMicro();
        var a = await AccountWithTotpAsync(now);
        var b = await AccountWithTotpAsync(now);
        var passkey = Passkey(a, RandomNumberGenerator.GetBytes(32), now);
        Assert.Equal(PasskeyInsertOutcome.Inserted, await _passkeys.InsertAsync(passkey, 10));

        var used = now.AddMinutes(1).AddTicks(7); // sub-microsecond ticks are dropped
        Assert.True(await _passkeys.TryRecordUseAsync(passkey.Id, 0, 5, true, used));
        Assert.False(await _passkeys.TryRecordUseAsync(passkey.Id, 0, 6, true, used)); // stale expectation: another use won
        Assert.True(await _passkeys.TryRecordUseAsync(passkey.Id, 5, uint.MaxValue, false, used)); // the counter is a uint32
        var read = (await _passkeys.FindByCredentialIdAsync(passkey.CredentialId))!;
        Assert.Equal((long)uint.MaxValue, read.SignCount);
        Assert.False(read.BackedUp);
        Assert.Equal(now.AddMinutes(1), read.LastUsedAt);

        Assert.False(await _passkeys.RenameAsync(b, passkey.Id, "theirs"));
        Assert.True(await _passkeys.RenameAsync(a, passkey.Id, "Phone"));
        Assert.True(await _passkeys.RenameAsync(a, passkey.Id, "Phone")); // unchanged name is still a match
        Assert.Equal("Phone", (await _passkeys.ListAsync(a)).Single().Name);
        Assert.False(await _passkeys.DeleteAsync(b, passkey.Id));
        Assert.True(await _passkeys.DeleteAsync(a, passkey.Id));
        Assert.False(await _passkeys.DeleteAsync(a, passkey.Id));
    }

    [Fact]
    public async Task Ceremonies_SingleUse_PurposeBound_Expire_MfaReplaces_CascadeWithTheirOwner()
    {
        await _fixture.ResetAsync();
        var now = AccountsTestContext.NowMicro();
        var a = await AccountWithTotpAsync(now);
        var handle = RandomNumberGenerator.GetBytes(32);
        var register = new WebAuthnChallenge(Guid.NewGuid(), WebAuthnChallengePurpose.Register, handle, a, null, RandomNumberGenerator.GetBytes(32), now, now.AddMinutes(5));
        await _ceremonies.CreateAsync(register);

        Assert.Null(await _ceremonies.FindActiveByHandleAsync(handle, WebAuthnChallengePurpose.Passwordless, now));
        var found = await _ceremonies.FindActiveByHandleAsync(handle, WebAuthnChallengePurpose.Register, now);
        Assert.Equal(register.Challenge, found!.Challenge);
        Assert.Equal(a, found.AccountId);
        Assert.Null(await _ceremonies.FindActiveByHandleAsync(handle, WebAuthnChallengePurpose.Register, now.AddMinutes(5)));
        Assert.False(await _ceremonies.TryClaimAsync(register.Id, now.AddMinutes(5))); // expired
        Assert.True(await _ceremonies.TryClaimAsync(register.Id, now));
        Assert.False(await _ceremonies.TryClaimAsync(register.Id, now));
        Assert.Null(await _ceremonies.FindActiveByHandleAsync(handle, WebAuthnChallengePurpose.Register, now));

        // Passwordless: anonymous; a registration cannot be bound to nothing, a passwordless one cannot name an account.
        var anonymous = new WebAuthnChallenge(Guid.NewGuid(), WebAuthnChallengePurpose.Passwordless, RandomNumberGenerator.GetBytes(32), null, null, RandomNumberGenerator.GetBytes(32), now, now.AddMinutes(5));
        await _ceremonies.CreateAsync(anonymous);
        await Assert.ThrowsAsync<ArgumentException>(() => _ceremonies.CreateAsync(anonymous with { Id = Guid.NewGuid(), AccountId = a }));
        await Assert.ThrowsAsync<ArgumentException>(() => _ceremonies.CreateAsync(register with { Id = Guid.NewGuid(), AccountId = null }));
        await Assert.ThrowsAsync<ArgumentException>(() => _ceremonies.CreateAsync(register with { Id = Guid.NewGuid(), Challenge = new byte[8] }));

        // MFA: one live ceremony per MFA challenge; asking again replaces it (the old id can no longer be claimed).
        var mfaId = Guid.NewGuid();
        await _mfa.CreateAsync(new MfaChallenge(mfaId, a, RandomNumberGenerator.GetBytes(32), RandomNumberGenerator.GetBytes(32), null, now, now.AddMinutes(5)));
        var firstMfa = new WebAuthnChallenge(Guid.NewGuid(), WebAuthnChallengePurpose.Mfa, null, a, mfaId, RandomNumberGenerator.GetBytes(32), now, now.AddMinutes(5));
        await _ceremonies.UpsertForMfaAsync(firstMfa);
        var secondMfa = firstMfa with { Id = Guid.NewGuid(), Challenge = RandomNumberGenerator.GetBytes(32) };
        await _ceremonies.UpsertForMfaAsync(secondMfa);
        var live = await _ceremonies.FindActiveForMfaAsync(mfaId, now);
        Assert.Equal(secondMfa.Id, live!.Id);
        Assert.Equal(secondMfa.Challenge, live.Challenge);
        Assert.False(await _ceremonies.TryClaimAsync(firstMfa.Id, now));
        Assert.True(await _ceremonies.TryClaimAsync(secondMfa.Id, now));
        Assert.Null(await _ceremonies.FindActiveForMfaAsync(mfaId, now));
        var third = firstMfa with { Id = Guid.NewGuid() };
        await _ceremonies.UpsertForMfaAsync(third); // re-armed after a claim: fresh and unclaimed
        Assert.Equal(third.Id, (await _ceremonies.FindActiveForMfaAsync(mfaId, now))!.Id);
        Assert.Equal(1L, await CountAsync("SELECT COUNT(*) FROM webauthn_challenges WHERE mfa_challenge_id = @mfaId", new { mfaId }));

        // Owners take their ceremonies with them: TOTP disable deletes the MFA challenges (cascade), account deletion the rest.
        Assert.True(await _totp.DisableAsync(a));
        Assert.Equal(0L, await CountAsync("SELECT COUNT(*) FROM webauthn_challenges WHERE mfa_challenge_id = @mfaId", new { mfaId }));
        await _fixture.ResetAsync();
        Assert.Equal(0L, await CountAsync("SELECT COUNT(*) FROM webauthn_challenges WHERE account_id IS NOT NULL", new { }));
        Assert.Equal(1L, await CountAsync("SELECT COUNT(*) FROM webauthn_challenges WHERE id = @Id", new { anonymous.Id }));
    }

    [Fact]
    public async Task Housekeeping_DeletesExpiredCeremonies_AtOnce_KeepsLiveOnes()
    {
        await _fixture.ResetAsync();
        await using (var c = await _fixture.ConnectionFactory.OpenConnectionAsync())
        {
            await c.ExecuteAsync("DELETE FROM webauthn_challenges;");
        }

        var now = AccountsTestContext.NowMicro();
        var expired = new WebAuthnChallenge(Guid.NewGuid(), WebAuthnChallengePurpose.Passwordless, RandomNumberGenerator.GetBytes(32), null, null, RandomNumberGenerator.GetBytes(32), now.AddMinutes(-6), now.AddMinutes(-1));
        var live = expired with { Id = Guid.NewGuid(), HandleVerifier = RandomNumberGenerator.GetBytes(32), CreatedAt = now, ExpiresAt = now.AddMinutes(5) };
        await _ceremonies.CreateAsync(expired);
        await _ceremonies.CreateAsync(live);

        var runner = new HousekeepingRunner(new HousekeepingStore(_fixture.RuntimeConnectionFactory), new HousekeepingOptions(), new RefreshTokenOptions(),
            new FakeTimeProvider(new DateTimeOffset(now)), NullLogger<HousekeepingRunner>.Instance);
        var result = await runner.RunOnceAsync();
        Assert.Equal(1, result.WebAuthnChallenges);
        Assert.Equal(0L, await CountAsync("SELECT COUNT(*) FROM webauthn_challenges WHERE id = @Id", new { expired.Id }));
        Assert.Equal(1L, await CountAsync("SELECT COUNT(*) FROM webauthn_challenges WHERE id = @Id", new { live.Id }));
    }
}
