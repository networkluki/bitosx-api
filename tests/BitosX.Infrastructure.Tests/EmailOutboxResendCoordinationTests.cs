using BitosX.Application.Abstractions.Persistence;
using BitosX.Application.Email;
using BitosX.Application.Verification;
using BitosX.Infrastructure.Accounts;
using BitosX.Infrastructure.Email;
using BitosX.Infrastructure.Tests.Email;
using Dapper;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;

namespace BitosX.Infrastructure.Tests;

[Collection("Persistence")]
public sealed class EmailOutboxResendCoordinationTests
{
    private readonly DatabaseFixture _fixture;
    private readonly AccountsTestContext _ctx;

    public EmailOutboxResendCoordinationTests(DatabaseFixture fixture)
    {
        _fixture = fixture;
        _ctx = new AccountsTestContext(fixture.ConnectionFactory);
    }

    private EmailOutboxDispatcher Dispatcher(FakeEmailSender sender, FakeTimeProvider clock)
    {
        var options = new EmailOutboxOptions();
        var composer = new VerificationEmailComposer(new EmailOptions { FromAddress = "b@x.io", PublicBaseUrl = "https://vault.bitosx.se" });
        return new EmailOutboxDispatcher(_ctx.OutboxStore, _ctx.Protector, sender, composer,
            options, new DefaultEmailRetryBackoff(options, () => 0.5), clock, NullLogger<EmailOutboxDispatcher>.Instance);
    }

    private PreparedChallenge Prepare(Guid accountId, string email, DateTime at)
        => new VerificationChallengeFactory(_ctx.Tokens, _ctx.Protector, new EmailVerificationSecurityOptions { Pepper = "x" })
            .Create(accountId, email, at);

    private async Task<T> ScalarAsync<T>(string sql, object p)
    {
        await using var c = await _fixture.ConnectionFactory.OpenConnectionAsync();
        return (T)Convert.ChangeType(await c.ExecuteScalarAsync(new CommandDefinition(sql, p)) ?? 0L, typeof(T));
    }

    [Fact]
    public async Task DispatcherClaimsFirst_ResendDoesNotInvalidateInFlightChallenge()
    {
        await _fixture.ResetAsync();
        var now = AccountsTestContext.NowMicro();
        var r = await _ctx.RegisterAsync(now);

        // Dispatcher claims A and holds a live lease.
        var claimed = await _ctx.OutboxStore.ClaimDueAsync(now, now.AddMinutes(1), "worker-1", 10);
        Assert.Single(claimed);

        // Resend while delivery is in flight → must not invalidate / create B.
        var prepared = Prepare(r.AccountId, r.Email, now);
        var outcome = await _ctx.VerificationStore.ReplaceActiveChallengeAsync(
            r.AccountId, prepared.Challenge, prepared.Outbox, now, TimeSpan.Zero);

        Assert.Equal(ResendOutcome.SkippedDeliveryInProgress, outcome);
        Assert.Equal(1L, await ScalarAsync<long>("SELECT COUNT(*) FROM email_verification_challenges WHERE id=@id AND invalidated_at IS NULL", new { id = r.ChallengeId }));
        Assert.Equal(0L, await ScalarAsync<long>("SELECT COUNT(*) FROM email_verification_challenges WHERE id=@id", new { id = prepared.Challenge.Id })); // no B
        Assert.Equal(1L, await ScalarAsync<long>("SELECT COUNT(*) FROM email_verification_challenges WHERE account_id=@a", new { a = r.AccountId }));

        // Dispatcher may now safely deliver A.
        var sender = new FakeEmailSender();
        var sent = await Dispatcher(sender, new FakeTimeProvider(now)).TryDeliverClaimedRowAsync(claimed[0]);
        Assert.True(sent);
        Assert.Single(sender.Sent);
    }

    [Fact]
    public async Task ResendLocksFirst_DispatcherCannotSendInvalidatedOldChallenge()
    {
        await _fixture.ResetAsync();
        var now = AccountsTestContext.NowMicro();
        var r = await _ctx.RegisterAsync(now);

        // No lease held → resend wins coordination, invalidates A, creates B.
        var prepared = Prepare(r.AccountId, r.Email, now);
        var outcome = await _ctx.VerificationStore.ReplaceActiveChallengeAsync(
            r.AccountId, prepared.Challenge, prepared.Outbox, now, TimeSpan.Zero);
        Assert.Equal(ResendOutcome.Replaced, outcome);

        var sender = new FakeEmailSender();
        await Dispatcher(sender, new FakeTimeProvider(now)).ProcessDueOnceAsync();

        Assert.Single(sender.Sent);                                        // only B
        Assert.Contains(prepared.TokenBase64Url, sender.Sent[0].TextBody);
        Assert.Equal(1L, await ScalarAsync<long>("SELECT COUNT(*) FROM email_outbox WHERE id=@id AND failed_at IS NOT NULL AND payload_ciphertext IS NULL", new { id = r.OutboxId })); // A terminal+erased
    }

    [Fact]
    public async Task ExpiredLease_AllowsResendRecovery_StaleANeverSends()
    {
        await _fixture.ResetAsync();
        var now = AccountsTestContext.NowMicro();
        var r = await _ctx.RegisterAsync(now);

        // Claim A with a short lease, then time advances past the lease.
        await _ctx.OutboxStore.ClaimDueAsync(now, now.AddSeconds(5), "dead-worker", 10);
        var later = now.AddSeconds(10); // lease (now+5s) has expired

        var prepared = Prepare(r.AccountId, r.Email, later);
        var outcome = await _ctx.VerificationStore.ReplaceActiveChallengeAsync(
            r.AccountId, prepared.Challenge, prepared.Outbox, later, TimeSpan.Zero);

        Assert.Equal(ResendOutcome.Replaced, outcome); // expired lease → resend may proceed
        Assert.Equal(1L, await ScalarAsync<long>("SELECT COUNT(*) FROM email_verification_challenges WHERE id=@id AND invalidated_at IS NOT NULL", new { id = r.ChallengeId }));

        var sender = new FakeEmailSender();
        await Dispatcher(sender, new FakeTimeProvider(later)).ProcessDueOnceAsync();
        Assert.Single(sender.Sent); // only B; stale A never sends
        Assert.Contains(prepared.TokenBase64Url, sender.Sent[0].TextBody);
    }

    [Fact]
    public void SmtpTimeout_IsStrictlyLessThanLeaseDuration()
    {
        // Valid: default lease 2min > 30s attempt + 10s margin.
        AccountsServiceCollectionExtensions.ValidateDeliveryTimeouts(
            new EmailOutboxOptions { LeaseDuration = TimeSpan.FromMinutes(2) },
            new SmtpOptions { AttemptTimeout = TimeSpan.FromSeconds(30) });

        // Invalid: lease not greater than attempt timeout + margin → fail closed.
        Assert.Throws<InvalidOperationException>(() =>
            AccountsServiceCollectionExtensions.ValidateDeliveryTimeouts(
                new EmailOutboxOptions { LeaseDuration = TimeSpan.FromSeconds(35) },
                new SmtpOptions { AttemptTimeout = TimeSpan.FromSeconds(30) }));
    }
}
