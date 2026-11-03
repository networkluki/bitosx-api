using System.Data;
using System.Security.Cryptography;
using System.Text;
using BitosX.Application.Abstractions.Persistence;
using BitosX.Application.Accounts;
using BitosX.Application.Mfa;
using BitosX.Infrastructure.Persistence;
using Dapper;
using Microsoft.Extensions.Time.Testing;

namespace BitosX.Infrastructure.Tests;

/// <summary>
/// "Locking read on a missing row, then INSERT" across DIFFERENT accounts (first vault upload, first TOTP
/// enrollment). Under REPEATABLE READ both transactions take the same gap lock and each insert waits on the
/// other's gap lock: InnoDB kills one with a deadlock (a 500 for that user). The stores now run these
/// transactions under READ COMMITTED (no gap lock on the missing row). Each test reproduces the interleaving
/// deterministically: a second transaction holds the REPEATABLE READ gap lock of an ADJACENT account id, the
/// store's insert waits on it, and the second transaction then inserts its own row — the exact step that
/// deadlocked before. With the fix both commit.
/// </summary>
[Collection("Persistence")]
public sealed class FirstInsertDeadlockTests
{
    private readonly DatabaseFixture _fixture;
    private readonly FakeTimeProvider _clock = new(new DateTimeOffset(2026, 11, 1, 12, 0, 0, TimeSpan.Zero));

    public FirstInsertDeadlockTests(DatabaseFixture fixture) => _fixture = fixture;

    /// <summary>Two accounts whose ids sort next to each other, so nothing lies in the gap between them.</summary>
    private async Task<(Guid Blocker, Guid Store)> AdjacentAccountsAsync()
    {
        var prefix = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(4));
        var blocker = Guid.Parse($"{prefix}-0000-4000-8000-000000000001");
        var store = Guid.Parse($"{prefix}-0000-4000-8000-000000000002");
        foreach (var id in new[] { blocker, store })
        {
            var email = $"gap-{id:N}@example.com";
            await _fixture.Accounts.AddAsync(new Account
            {
                Id = id, Email = email, NormalizedEmail = EmailNormalizer.Normalize(email),
                CreatedAt = _clock.GetUtcNow().UtcDateTime, UpdatedAt = _clock.GetUtcNow().UtcDateTime,
            });
        }

        return (blocker, store);
    }

    private static async Task AssertBlockedAsync(Task operation)
    {
        // The store's insert must be waiting on the blocker's gap lock (it reached the step that used to deadlock).
        var first = await Task.WhenAny(operation, Task.Delay(TimeSpan.FromSeconds(1.5)));
        Assert.NotSame(operation, first);
    }

    [Fact]
    public async Task FirstVaultUploads_OfAdjacentAccounts_DoNotDeadlock()
    {
        var (blocker, storeAccount) = await AdjacentAccountsAsync();
        var store = new EnvelopeStore(_fixture.RuntimeConnectionFactory, _clock);
        var envelope = Encoding.UTF8.GetBytes("{\"version\":1,\"ciphertext\":\"AAAA\"}");

        await using var connection = await _fixture.ConnectionFactory.OpenConnectionAsync();
        await using var tx = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead);
        Assert.Null(await connection.QuerySingleOrDefaultAsync<long?>(
            "SELECT revision FROM vault_blobs WHERE account_id = @blocker FOR UPDATE;", new { blocker }, tx)); // gap lock

        var upload = store.UpsertAsync(storeAccount, 0, envelope, SHA256.HashData(envelope));
        await AssertBlockedAsync(upload);

        await connection.ExecuteAsync(
            """
            INSERT INTO vault_blobs (account_id, revision, size_bytes, fingerprint, envelope, created_at, updated_at)
            VALUES (@blocker, 1, @size, @fingerprint, @envelope, UTC_TIMESTAMP(6), UTC_TIMESTAMP(6));
            """, new { blocker, size = envelope.Length, fingerprint = SHA256.HashData(envelope), envelope }, tx);
        await tx.CommitAsync();

        var result = await upload;
        Assert.Equal(EnvelopeUpsertOutcome.Stored, result.Outcome);
        Assert.Equal(1, result.Revision);
    }

    [Fact]
    public async Task FirstTotpEnrollments_OfAdjacentAccounts_DoNotDeadlock()
    {
        var (blocker, storeAccount) = await AdjacentAccountsAsync();
        var store = new TotpStore(_fixture.RuntimeConnectionFactory);
        var secret = new ProtectedTotpSecret(1, RandomNumberGenerator.GetBytes(12), RandomNumberGenerator.GetBytes(20), RandomNumberGenerator.GetBytes(16));

        await using var connection = await _fixture.ConnectionFactory.OpenConnectionAsync();
        await using var tx = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead);
        Assert.Null(await connection.QuerySingleOrDefaultAsync<DateTime?>(
            "SELECT confirmed_at FROM account_totp WHERE account_id = @blocker FOR UPDATE;", new { blocker }, tx)); // gap lock

        var enroll = store.StorePendingAsync(storeAccount, secret, _clock.GetUtcNow().UtcDateTime);
        await AssertBlockedAsync(enroll);

        await connection.ExecuteAsync(
            """
            INSERT INTO account_totp (account_id, secret_version, secret_nonce, secret_ciphertext, secret_tag, created_at, confirmed_at, last_used_step)
            VALUES (@blocker, 1, RANDOM_BYTES(12), RANDOM_BYTES(20), RANDOM_BYTES(16), UTC_TIMESTAMP(6), NULL, NULL);
            """, new { blocker }, tx);
        await tx.CommitAsync();

        Assert.Equal(TotpPendingOutcome.Stored, await enroll);
    }

    [Fact]
    public async Task ManyFirstUploads_OfDifferentAccounts_AllSucceed()
    {
        var store = new EnvelopeStore(_fixture.RuntimeConnectionFactory, _clock);
        var accounts = new List<Guid>();
        for (var i = 0; i < 16; i++)
        {
            var (a, b) = await AdjacentAccountsAsync();
            accounts.Add(a);
            accounts.Add(b);
        }

        var body = Encoding.UTF8.GetBytes("{\"version\":1,\"ciphertext\":\"" + new string('x', 256 * 1024) + "\"}");
        var results = await Task.WhenAll(accounts.Select(a => store.UpsertAsync(a, 0, body, SHA256.HashData(body))));

        Assert.All(results, r => Assert.Equal(EnvelopeUpsertOutcome.Stored, r.Outcome));
    }

    [Fact]
    public async Task ConcurrentFirstEnrollments_OfOneAccount_SerializeOnTheAccountRow()
    {
        var (_, account) = await AdjacentAccountsAsync();
        var store = new TotpStore(_fixture.RuntimeConnectionFactory);

        var outcomes = await Task.WhenAll(Enumerable.Range(0, 8).Select(_ => store.StorePendingAsync(
            account, new ProtectedTotpSecret(1, RandomNumberGenerator.GetBytes(12), RandomNumberGenerator.GetBytes(20), RandomNumberGenerator.GetBytes(16)),
            _clock.GetUtcNow().UtcDateTime)));

        Assert.All(outcomes, o => Assert.Equal(TotpPendingOutcome.Stored, o));
        Assert.NotNull(await store.GetAsync(account));
    }
}
