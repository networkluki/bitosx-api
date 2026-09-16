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
}
