using BitosX.Application.Email;
using BitosX.Application.Verification;
using BitosX.Infrastructure.Email;
using Dapper;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;

namespace BitosX.Infrastructure.Tests.Email;

internal sealed class FakeEmailSender : IEmailSender
{
    public List<EmailMessage> Sent { get; } = [];
    public EmailSendResult Result { get; set; } = EmailSendResult.Sent;

    public Task<EmailSendResult> SendAsync(EmailMessage message, CancellationToken ct = default)
    {
        if (Result == EmailSendResult.Sent) Sent.Add(message);
        return Task.FromResult(Result);
    }
}

[Collection("Persistence")]
public sealed class EmailOutboxDispatcherTests
{
    private readonly DatabaseFixture _fixture;
    private readonly AccountsTestContext _ctx;

    public EmailOutboxDispatcherTests(DatabaseFixture fixture)
    {
        _fixture = fixture;
        _ctx = new AccountsTestContext(fixture.ConnectionFactory);
    }

    private EmailOutboxDispatcher Dispatcher(FakeEmailSender sender, FakeTimeProvider clock, EmailOutboxOptions? opts = null)
    {
        var options = opts ?? new EmailOutboxOptions();
        var composer = new VerificationEmailComposer(new EmailOptions { FromAddress = "b@x.io", PublicBaseUrl = "https://vault.bitosx.se" });
        return new EmailOutboxDispatcher(_ctx.OutboxStore, _ctx.Protector, sender, composer,
            options, new DefaultEmailRetryBackoff(options, () => 0.5),
            clock, NullLogger<EmailOutboxDispatcher>.Instance);
    }

    private async Task<T?> ScalarAsync<T>(string sql, object p)
    {
        await using var c = await _fixture.ConnectionFactory.OpenConnectionAsync();
        return await c.ExecuteScalarAsync<T>(new CommandDefinition(sql, p));
    }

    private async Task ExecAsync(string sql, object p)
    {
        await using var c = await _fixture.ConnectionFactory.OpenConnectionAsync();
        await c.ExecuteAsync(new CommandDefinition(sql, p));
    }

    [Fact]
    public async Task ActiveChallenge_IsDelivered_PayloadErased()
    {
        await _fixture.ResetAsync();
        var now = AccountsTestContext.NowMicro();
        var clock = new FakeTimeProvider(now);
        var r = await _ctx.RegisterAsync(now);
        var sender = new FakeEmailSender();

        await Dispatcher(sender, clock).ProcessDueOnceAsync();

        Assert.Single(sender.Sent);
        Assert.Contains(r.Token, sender.Sent[0].TextBody); // the actual verification token
        Assert.Equal(1, await ScalarAsync<long>("SELECT COUNT(*) FROM email_outbox WHERE id=@id AND sent_at IS NOT NULL AND payload_ciphertext IS NULL", new { id = r.OutboxId }));
    }

    [Fact]
    public async Task ExpiredChallenge_IsNotDelivered_MarkedFailed()
    {
        await _fixture.ResetAsync();
        var now = AccountsTestContext.NowMicro();
        var r = await _ctx.RegisterAsync(now, ttl: TimeSpan.FromMinutes(30));
        var sender = new FakeEmailSender();
        var clock = new FakeTimeProvider(now.AddMinutes(31)); // past expiry

        await Dispatcher(sender, clock).ProcessDueOnceAsync();

        Assert.Empty(sender.Sent);
        Assert.Equal(1, await ScalarAsync<long>("SELECT COUNT(*) FROM email_outbox WHERE id=@id AND failed_at IS NOT NULL AND payload_ciphertext IS NULL", new { id = r.OutboxId }));
    }

    [Fact]
    public async Task InvalidatedChallenge_StaleOutbox_NotSent_And_ActiveOneSentOnce()
    {
        await _fixture.ResetAsync();
        var now = AccountsTestContext.NowMicro();
        var clock = new FakeTimeProvider(now);
        var r = await _ctx.RegisterAsync(now); // challenge A + outbox A

        // Resend at +5m → A invalidated, B active with its own outbox.
        var later = now.AddMinutes(5);
        var token = _ctx.Tokens.GenerateToken();
        var newChallengeId = Guid.NewGuid();
        var newOutboxId = Guid.NewGuid();
        var newChallenge = new EmailVerificationChallenge { Id = newChallengeId, AccountId = r.AccountId, TokenHash = token.VerifierHash, CreatedAt = later, ExpiresAt = later.AddMinutes(30) };
        var payload = _ctx.Protector.Protect(new OutboxPayload(1, r.AccountId, token.TokenBase64Url, later.AddMinutes(30), r.Email),
            new OutboxAad(newOutboxId, 1, OutboxMessageTypes.EmailVerification, r.Email));
        var newOutbox = new EmailOutboxMessage(newOutboxId, newChallengeId, OutboxMessageTypes.EmailVerification, r.Email, payload, later, later);
        await _ctx.VerificationStore.ReplaceActiveChallengeAsync(r.AccountId, newChallenge, newOutbox, later, TimeSpan.FromSeconds(60));

        var sender = new FakeEmailSender();
        await Dispatcher(sender, new FakeTimeProvider(later)).ProcessDueOnceAsync();

        // Only the active challenge B's link is sent; stale A is not.
        Assert.Single(sender.Sent);
        Assert.Contains(token.TokenBase64Url, sender.Sent[0].TextBody);
        Assert.Equal(1, await ScalarAsync<long>("SELECT COUNT(*) FROM email_outbox WHERE id=@id AND failed_at IS NOT NULL AND payload_ciphertext IS NULL", new { id = r.OutboxId })); // A failed+erased
        Assert.Equal(1, await ScalarAsync<long>("SELECT COUNT(*) FROM email_outbox WHERE id=@id AND sent_at IS NOT NULL", new { id = newOutboxId }));        // B sent
    }

    [Fact]
    public async Task RecipientTamper_FailsIntegrity_NotSent_PayloadErased()
    {
        await _fixture.ResetAsync();
        var now = AccountsTestContext.NowMicro();
        var r = await _ctx.RegisterAsync(now);

        // Tamper the row recipient (attacker with DB write, no EmailOutboxKey).
        await ExecAsync("UPDATE email_outbox SET recipient_email=@e WHERE id=@id", new { e = "attacker@evil.example", id = r.OutboxId });

        var sender = new FakeEmailSender();
        await Dispatcher(sender, new FakeTimeProvider(now)).ProcessDueOnceAsync();

        Assert.Empty(sender.Sent); // AAD authentication fails → not sent
        Assert.Equal(1, await ScalarAsync<long>("SELECT COUNT(*) FROM email_outbox WHERE id=@id AND failed_at IS NOT NULL AND payload_ciphertext IS NULL", new { id = r.OutboxId }));
    }

    [Fact]
    public async Task TransientFailure_Reschedules_ThenFailsAfterMaxAttempts()
    {
        await _fixture.ResetAsync();
        var now = AccountsTestContext.NowMicro();
        var r = await _ctx.RegisterAsync(now);
        var sender = new FakeEmailSender { Result = EmailSendResult.Failed };
        var opts = new EmailOutboxOptions { MaxAttempts = 2, BackoffBase = TimeSpan.FromSeconds(5) };

        // Attempt 1 (attempt_count 0 -> reschedule)
        await Dispatcher(sender, new FakeTimeProvider(now), opts).ProcessDueOnceAsync();
        Assert.Equal(1, await ScalarAsync<long>("SELECT COUNT(*) FROM email_outbox WHERE id=@id AND attempt_count=1 AND failed_at IS NULL AND sent_at IS NULL", new { id = r.OutboxId }));

        // Attempt 2 (attempt_count 1, nextAttempt 2 >= MaxAttempts -> failed)
        await Dispatcher(sender, new FakeTimeProvider(now.AddMinutes(1)), opts).ProcessDueOnceAsync();
        Assert.Equal(1, await ScalarAsync<long>("SELECT COUNT(*) FROM email_outbox WHERE id=@id AND failed_at IS NOT NULL AND payload_ciphertext IS NULL", new { id = r.OutboxId }));
        Assert.Empty(sender.Sent);
    }

    [Fact]
    public async Task InvalidatedBetweenClaimAndSend_FreshRecheck_DoesNotSend()
    {
        await _fixture.ResetAsync();
        var now = AccountsTestContext.NowMicro();
        var r = await _ctx.RegisterAsync(now);
        var sender = new FakeEmailSender();
        var dispatcher = Dispatcher(sender, new FakeTimeProvider(now));

        // Claim the row (active snapshot), then a concurrent resend invalidates the challenge.
        var claimed = await _ctx.OutboxStore.ClaimDueAsync(now, now.AddMinutes(1), "w", 10);
        Assert.Single(claimed);
        await ExecAsync("UPDATE email_verification_challenges SET invalidated_at=@t WHERE id=@id", new { t = now, id = r.ChallengeId });

        // Fresh pre-send re-check must reject despite the stale "active" snapshot.
        var sent = await dispatcher.TryDeliverClaimedRowAsync(claimed[0]);

        Assert.False(sent);
        Assert.Empty(sender.Sent);
        Assert.Equal(1, await ScalarAsync<long>("SELECT COUNT(*) FROM email_outbox WHERE id=@id AND failed_at IS NOT NULL AND payload_ciphertext IS NULL", new { id = r.OutboxId }));
    }

    [Fact]
    public async Task ExpiredBetweenClaimAndSend_FreshRecheck_DoesNotSend()
    {
        await _fixture.ResetAsync();
        var now = AccountsTestContext.NowMicro();
        var r = await _ctx.RegisterAsync(now, ttl: TimeSpan.FromMinutes(30));
        var sender = new FakeEmailSender();
        var clock = new FakeTimeProvider(now);
        var dispatcher = Dispatcher(sender, clock);

        var claimed = await _ctx.OutboxStore.ClaimDueAsync(now, now.AddMinutes(1), "w", 10);
        Assert.Single(claimed);

        // Time advances past expiry before delivery; the fresh per-row timestamp rejects it.
        clock.SetUtcNow(now.AddMinutes(31));
        var sent = await dispatcher.TryDeliverClaimedRowAsync(claimed[0]);

        Assert.False(sent);
        Assert.Empty(sender.Sent);
        Assert.Equal(1, await ScalarAsync<long>("SELECT COUNT(*) FROM email_outbox WHERE id=@id AND failed_at IS NOT NULL AND payload_ciphertext IS NULL", new { id = r.OutboxId }));
    }

    [Fact]
    public async Task SentRow_IsNotReprocessed_NoDuplicateSend()
    {
        await _fixture.ResetAsync();
        var now = AccountsTestContext.NowMicro();
        var r = await _ctx.RegisterAsync(now);
        var sender = new FakeEmailSender();
        var dispatcher = Dispatcher(sender, new FakeTimeProvider(now));

        await dispatcher.ProcessDueOnceAsync();
        await dispatcher.ProcessDueOnceAsync(); // terminal row is not re-claimed

        Assert.Single(sender.Sent);
        Assert.Equal(1, await ScalarAsync<long>("SELECT COUNT(*) FROM email_verification_challenges WHERE id=@id", new { id = r.ChallengeId })); // no 2nd challenge
    }

    [Fact]
    public async Task ARowWhoseLeasePassedToAnotherWorker_IsNotSent()
    {
        await _fixture.ResetAsync();
        var now = AccountsTestContext.NowMicro();
        await _ctx.RegisterAsync(now);
        var sender = new FakeEmailSender();
        var clock = new FakeTimeProvider(now);
        var dispatcher = Dispatcher(sender, clock);

        // This worker claimed the batch, then spent longer than the lease on earlier rows: another worker took it.
        var claimed = await _ctx.OutboxStore.ClaimDueAsync(now, now.AddSeconds(5), dispatcher.WorkerId, 10);
        Assert.Single(await _ctx.OutboxStore.ClaimDueAsync(now.AddSeconds(10), now.AddMinutes(2), "worker-2", 10));
        clock.SetUtcNow(now.AddSeconds(10));

        Assert.False(await dispatcher.TryDeliverClaimedRowAsync(claimed[0]));
        Assert.Empty(sender.Sent); // never two concurrent sends of one row
    }

    [Fact]
    public async Task EachSend_HoldsAFreshLease_EvenLateInABatch()
    {
        await _fixture.ResetAsync();
        var now = AccountsTestContext.NowMicro();
        var r = await _ctx.RegisterAsync(now);
        var clock = new FakeTimeProvider(now);
        var probe = new LeaseProbeSender(_fixture, r.OutboxId);
        var options = new EmailOutboxOptions();
        var composer = new VerificationEmailComposer(new EmailOptions { FromAddress = "b@x.io", PublicBaseUrl = "https://vault.bitosx.se" });
        var dispatcher = new EmailOutboxDispatcher(_ctx.OutboxStore, _ctx.Protector, probe, composer,
            options, new DefaultEmailRetryBackoff(options, () => 0.5), clock, NullLogger<EmailOutboxDispatcher>.Instance);

        var claimed = await _ctx.OutboxStore.ClaimDueAsync(now, now.AddSeconds(5), dispatcher.WorkerId, 10);
        clock.SetUtcNow(now.AddMinutes(10)); // the batch lease is long gone when this row's turn comes

        Assert.True(await dispatcher.TryDeliverClaimedRowAsync(claimed[0]));
        Assert.Equal(now.AddMinutes(10) + options.LeaseDuration, probe.LockedUntilDuringSend); // renewed right before the send
    }

    private sealed class LeaseProbeSender(DatabaseFixture fixture, Guid outboxId) : IEmailSender
    {
        public DateTime? LockedUntilDuringSend { get; private set; }

        public async Task<EmailSendResult> SendAsync(EmailMessage message, CancellationToken ct = default)
        {
            await using var c = await fixture.ConnectionFactory.OpenConnectionAsync(ct);
            LockedUntilDuringSend = await c.ExecuteScalarAsync<DateTime?>(new CommandDefinition("SELECT locked_until FROM email_outbox WHERE id=@outboxId", new { outboxId }, cancellationToken: ct));
            return EmailSendResult.Sent;
        }
    }
}
