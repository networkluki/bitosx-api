using Dapper;

namespace BitosX.Infrastructure.Tests;

[Collection("Persistence")]
public sealed class EmailOutboxStoreTests
{
    private readonly DatabaseFixture _fixture;
    private readonly AccountsTestContext _ctx;

    public EmailOutboxStoreTests(DatabaseFixture fixture)
    {
        _fixture = fixture;
        _ctx = new AccountsTestContext(fixture.ConnectionFactory);
    }

    private async Task<T?> ScalarAsync<T>(string sql, object p)
    {
        await using var c = await _fixture.ConnectionFactory.OpenConnectionAsync();
        return await c.ExecuteScalarAsync<T>(new CommandDefinition(sql, p));
    }

    [Fact]
    public async Task ClaimDue_Leases_And_SecondClaimGetsNothing()
    {
        await _fixture.ResetAsync();
        var now = AccountsTestContext.NowMicro();
        var r = await _ctx.RegisterAsync(now);

        var lease = now.AddMinutes(1);
        var first = await _ctx.OutboxStore.ClaimDueAsync(now, lease, "worker-1", 10);
        Assert.Single(first);
        Assert.Equal(r.OutboxId, first[0].Id);

        // Row is now leased until `lease`; a second claim at the same time sees nothing.
        var second = await _ctx.OutboxStore.ClaimDueAsync(now, lease, "worker-2", 10);
        Assert.Empty(second);
    }

    [Fact]
    public async Task MarkSent_ErasesPayload_KeepsMetadata()
    {
        await _fixture.ResetAsync();
        var now = AccountsTestContext.NowMicro();
        var r = await _ctx.RegisterAsync(now);

        await _ctx.OutboxStore.MarkSentAndErasePayloadAsync(r.OutboxId, now);

        Assert.Equal(1, await ScalarAsync<long>("SELECT COUNT(*) FROM email_outbox WHERE id=@id AND sent_at IS NOT NULL AND payload_ciphertext IS NULL AND payload_nonce IS NULL AND payload_tag IS NULL", new { id = r.OutboxId }));
    }

    [Fact]
    public async Task MarkFailed_ErasesPayload()
    {
        await _fixture.ResetAsync();
        var now = AccountsTestContext.NowMicro();
        var r = await _ctx.RegisterAsync(now);

        await _ctx.OutboxStore.MarkFailedAndErasePayloadAsync(r.OutboxId, now);

        Assert.Equal(1, await ScalarAsync<long>("SELECT COUNT(*) FROM email_outbox WHERE id=@id AND failed_at IS NOT NULL AND payload_ciphertext IS NULL", new { id = r.OutboxId }));
    }

    [Fact]
    public async Task Reschedule_AdvancesAvailableAt_ReleasesLease()
    {
        await _fixture.ResetAsync();
        var now = AccountsTestContext.NowMicro();
        var r = await _ctx.RegisterAsync(now);
        await _ctx.OutboxStore.ClaimDueAsync(now, now.AddMinutes(1), "w", 10);

        var next = now.AddMinutes(2);
        await _ctx.OutboxStore.RescheduleAsync(r.OutboxId, next, now);

        Assert.Equal(1, await ScalarAsync<long>("SELECT COUNT(*) FROM email_outbox WHERE id=@id AND attempt_count=1 AND locked_until IS NULL", new { id = r.OutboxId }));
    }

    [Fact]
    public async Task FailAndEraseIneligible_TargetsExpiredOrInvalidatedChallenges()
    {
        await _fixture.ResetAsync();
        var now = AccountsTestContext.NowMicro();
        var r = await _ctx.RegisterAsync(now, ttl: TimeSpan.FromMinutes(30));

        var afterExpiry = now.AddMinutes(31);
        var affected = await _ctx.OutboxStore.FailAndEraseIneligibleAsync(afterExpiry);

        Assert.True(affected >= 1);
        Assert.Equal(1, await ScalarAsync<long>("SELECT COUNT(*) FROM email_outbox WHERE id=@id AND failed_at IS NOT NULL AND payload_ciphertext IS NULL", new { id = r.OutboxId }));
    }

    [Fact]
    public async Task DeleteSanitizedOlderThan_RemovesOldTerminalRows()
    {
        await _fixture.ResetAsync();
        var now = AccountsTestContext.NowMicro();
        var r = await _ctx.RegisterAsync(now.AddDays(-8)); // created 8 days ago
        await _ctx.OutboxStore.MarkSentAndErasePayloadAsync(r.OutboxId, now.AddDays(-8));

        var deleted = await _ctx.OutboxStore.DeleteSanitizedOlderThanAsync(now.AddDays(-7));
        Assert.True(deleted >= 1);
        Assert.Equal(0, await ScalarAsync<long>("SELECT COUNT(*) FROM email_outbox WHERE id=@id", new { id = r.OutboxId }));
    }

    [Fact]
    public async Task ALongestAllowedNonAsciiAddress_FitsThePayloadColumn()
    {
        // 320 UTF-16 units, almost all non-ASCII: the default JSON encoder escapes each as \uXXXX (6 bytes),
        // about 2.1 KB of plaintext; the old VARBINARY(512) column refused the insert (a 500 at registration).
        var domain = "@example.com";
        var local = new string('é', Application.Accounts.EmailAddressValidator.MaxLength - domain.Length);
        var email = local + domain;
        Assert.True(Application.Accounts.EmailAddressValidator.IsValid(email));

        var r = await _ctx.RegisterAsync(AccountsTestContext.NowMicro(), emailAddress: email);

        var size = await ScalarAsync<long>("SELECT LENGTH(payload_ciphertext) FROM email_outbox WHERE id=@id", new { id = r.OutboxId });
        Assert.True(size > 512, $"payload was {size} bytes");
        Assert.True(size <= 4096);
    }

    [Fact]
    public async Task RenewLease_OnlyForTheOwningWorker_AndOnlyWhileNonTerminal()
    {
        await _fixture.ResetAsync();
        var now = AccountsTestContext.NowMicro();
        var r = await _ctx.RegisterAsync(now);
        await _ctx.OutboxStore.ClaimDueAsync(now, now.AddSeconds(5), "worker-1", 10);

        Assert.True(await _ctx.OutboxStore.RenewLeaseAsync(r.OutboxId, "worker-1", now.AddMinutes(2)));
        Assert.Equal(1, await ScalarAsync<long>("SELECT COUNT(*) FROM email_outbox WHERE id=@id AND locked_until=@t", new { id = r.OutboxId, t = now.AddMinutes(2) }));
        Assert.False(await _ctx.OutboxStore.RenewLeaseAsync(r.OutboxId, "worker-2", now.AddMinutes(3)));

        await _ctx.OutboxStore.MarkSentAndErasePayloadAsync(r.OutboxId, now);
        Assert.False(await _ctx.OutboxStore.RenewLeaseAsync(r.OutboxId, "worker-1", now.AddMinutes(3)));
    }

    [Fact]
    public async Task Cleanup_WorksInBatches_AndLeavesActiveRowsAlone()
    {
        await _fixture.ResetAsync();
        var now = AccountsTestContext.NowMicro();
        var old = new List<Guid>();
        for (var i = 0; i < 3; i++)
        {
            var r = await _ctx.RegisterAsync(now.AddDays(-10), ttl: TimeSpan.FromMinutes(30));
            old.Add(r.OutboxId);
        }

        var active = await _ctx.RegisterAsync(now, ttl: TimeSpan.FromMinutes(30));

        // Old rows' challenges expired long ago: the sweep fails + erases them, then retention deletes them.
        Assert.Equal(3, await _ctx.OutboxStore.FailAndEraseIneligibleAsync(now));
        Assert.Equal(3, await _ctx.OutboxStore.DeleteSanitizedOlderThanAsync(now.AddDays(-7)));
        Assert.Equal(0, await ScalarAsync<long>("SELECT COUNT(*) FROM email_outbox WHERE id IN @old", new { old }));
        Assert.Equal(1, await ScalarAsync<long>("SELECT COUNT(*) FROM email_outbox WHERE id=@id AND failed_at IS NULL AND payload_ciphertext IS NOT NULL", new { id = active.OutboxId }));
    }
}
