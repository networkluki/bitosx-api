using System.Security.Cryptography;
using System.Text;
using BitosX.Application.Abstractions.Persistence;
using BitosX.Application.Accounts;
using BitosX.Infrastructure.Persistence;
using Microsoft.Extensions.Time.Testing;

namespace BitosX.Infrastructure.Tests;

/// <summary>
/// The envelope store against the real test database: revisions are compare-and-set under a row
/// lock, bytes come back exactly as stored, the row follows the account, and nothing is written on
/// a conflict or for a missing account.
/// </summary>
[Collection("Persistence")]
public sealed class EnvelopeStoreTests : IAsyncLifetime
{
    private readonly DatabaseFixture _fixture;
    private readonly FakeTimeProvider _clock = new(new DateTimeOffset(2026, 10, 20, 12, 0, 0, TimeSpan.Zero));
    private EnvelopeStore _store = null!;

    public EnvelopeStoreTests(DatabaseFixture fixture) => _fixture = fixture;

    public async Task InitializeAsync()
    {
        await _fixture.ResetAsync();
        _store = new EnvelopeStore(_fixture.ConnectionFactory, _clock);
    }

    public Task DisposeAsync() => Task.CompletedTask;

    private static byte[] Bytes(string text) => Encoding.UTF8.GetBytes(text);

    private async Task<Guid> NewAccountAsync()
    {
        var email = $"sync-{Guid.NewGuid():N}@example.com";
        var account = new Account
        {
            Id = Guid.NewGuid(),
            Email = email,
            NormalizedEmail = EmailNormalizer.Normalize(email),
            CreatedAt = _clock.GetUtcNow().UtcDateTime,
            UpdatedAt = _clock.GetUtcNow().UtcDateTime,
        };
        await _fixture.Accounts.AddAsync(account);
        return account.Id;
    }

    [Fact]
    public async Task NothingStored_ReadsAsNull()
    {
        var account = await NewAccountAsync();

        Assert.Null(await _store.GetAsync(account, includeEnvelope: false));
        Assert.Null(await _store.GetAsync(account, includeEnvelope: true));
        Assert.False(await _store.DeleteAsync(account));
    }

    [Fact]
    public async Task FirstUpload_AgainstZero_IsRevisionOne_AndComesBackByteForByte()
    {
        var account = await NewAccountAsync();
        var envelope = Bytes("{\"version\":1,\"ciphertext\":\"AAAA\"}");
        var fingerprint = SHA256.HashData(envelope);

        var result = await _store.UpsertAsync(account, 0, envelope, fingerprint);

        Assert.Equal(EnvelopeUpsertOutcome.Stored, result.Outcome);
        Assert.Equal(1, result.Revision);
        Assert.Equal(_clock.GetUtcNow().UtcDateTime, result.UpdatedAt);

        var status = await _store.GetAsync(account, includeEnvelope: false);
        Assert.NotNull(status);
        Assert.Null(status!.Envelope);
        Assert.Equal(1, status.Revision);
        Assert.Equal(envelope.Length, status.SizeBytes);
        Assert.Equal(fingerprint, status.Fingerprint);

        var full = await _store.GetAsync(account, includeEnvelope: true);
        Assert.Equal(envelope, full!.Envelope);
    }

    [Fact]
    public async Task Upload_AgainstTheCurrentRevision_Advances_AndReplacesTheBytes()
    {
        var account = await NewAccountAsync();
        var first = Bytes("{\"version\":1,\"ciphertext\":\"AAAA\"}");
        var second = Bytes("{\"version\":1,\"ciphertext\":\"BBBB\"}");
        await _store.UpsertAsync(account, 0, first, SHA256.HashData(first));
        _clock.Advance(TimeSpan.FromMinutes(1));

        var result = await _store.UpsertAsync(account, 1, second, SHA256.HashData(second));

        Assert.Equal(EnvelopeUpsertOutcome.Stored, result.Outcome);
        Assert.Equal(2, result.Revision);
        var stored = await _store.GetAsync(account, includeEnvelope: true);
        Assert.Equal(2, stored!.Revision);
        Assert.Equal(second, stored.Envelope);
        Assert.Equal(SHA256.HashData(second), stored.Fingerprint);
        Assert.True(stored.UpdatedAt > stored.CreatedAt);
    }

    [Theory]
    [InlineData(0)]   // "never uploaded" while the server already holds one
    [InlineData(2)]   // a revision the server never issued
    public async Task Upload_AgainstAnotherRevision_IsAConflict_AndChangesNothing(long baseRevision)
    {
        var account = await NewAccountAsync();
        var first = Bytes("{\"version\":1,\"ciphertext\":\"AAAA\"}");
        await _store.UpsertAsync(account, 0, first, SHA256.HashData(first));
        var attempt = Bytes("{\"version\":1,\"ciphertext\":\"CCCC\"}");

        var result = await _store.UpsertAsync(account, baseRevision, attempt, SHA256.HashData(attempt));

        Assert.Equal(EnvelopeUpsertOutcome.Conflict, result.Outcome);
        Assert.Equal(1, result.Revision);
        var stored = await _store.GetAsync(account, includeEnvelope: true);
        Assert.Equal(1, stored!.Revision);
        Assert.Equal(first, stored.Envelope);
    }

    [Fact]
    public async Task TwoDevices_UploadingAtOnce_ExactlyOneWins()
    {
        var account = await NewAccountAsync();
        var a = Bytes("{\"version\":1,\"ciphertext\":\"AAAA\"}");
        var b = Bytes("{\"version\":1,\"ciphertext\":\"BBBB\"}");

        var results = await Task.WhenAll(
            Enumerable.Range(0, 8).Select(i => _store.UpsertAsync(account, 0, i % 2 == 0 ? a : b, SHA256.HashData(i % 2 == 0 ? a : b))));

        Assert.Equal(1, results.Count(r => r.Outcome == EnvelopeUpsertOutcome.Stored));
        Assert.Equal(7, results.Count(r => r.Outcome == EnvelopeUpsertOutcome.Conflict));
        Assert.All(results.Where(r => r.Outcome == EnvelopeUpsertOutcome.Conflict), r => Assert.Equal(1, r.Revision));
        var stored = await _store.GetAsync(account, includeEnvelope: true);
        Assert.Equal(1, stored!.Revision);
        Assert.True(stored.Envelope!.AsSpan().SequenceEqual(a) || stored.Envelope.AsSpan().SequenceEqual(b));
    }

    [Fact]
    public async Task Upload_ForAnUnknownAccount_WritesNothing()
    {
        var envelope = Bytes("{\"version\":1}");

        var result = await _store.UpsertAsync(Guid.NewGuid(), 0, envelope, SHA256.HashData(envelope));

        Assert.Equal(EnvelopeUpsertOutcome.NoAccount, result.Outcome);
    }

    [Fact]
    public async Task Delete_ClearsTheEnvelope_AndIsIdempotent()
    {
        var account = await NewAccountAsync();
        var envelope = Bytes("{\"version\":1}");
        await _store.UpsertAsync(account, 0, envelope, SHA256.HashData(envelope));

        Assert.True(await _store.DeleteAsync(account));
        Assert.False(await _store.DeleteAsync(account));
        Assert.Null(await _store.GetAsync(account, includeEnvelope: false));
        Assert.Null(await _store.GetAsync(account, includeEnvelope: true));

        // Nothing is stored, so the next upload names base revision 0 — and continues the numbering.
        var again = await _store.UpsertAsync(account, 0, envelope, SHA256.HashData(envelope));
        Assert.Equal(EnvelopeUpsertOutcome.Stored, again.Outcome);
        Assert.Equal(2, again.Revision);
    }

    [Fact]
    public async Task RevisionsNeverRestart_AfterADelete_AndAStaleDeviceConflicts()
    {
        var account = await NewAccountAsync();
        var a = Bytes("{\"version\":1,\"ciphertext\":\"AAAA\"}");
        var b = Bytes("{\"version\":1,\"ciphertext\":\"BBBB\"}");
        await _store.UpsertAsync(account, 0, a, SHA256.HashData(a)); // 1 (device B last saw this)
        await _store.UpsertAsync(account, 1, a, SHA256.HashData(a)); // 2
        await _store.UpsertAsync(account, 2, a, SHA256.HashData(a)); // 3
        Assert.True(await _store.DeleteAsync(account));

        // While nothing is stored, only base 0 is accepted; a stale base sees current revision 0.
        var stale = await _store.UpsertAsync(account, 3, b, SHA256.HashData(b));
        Assert.Equal(EnvelopeUpsertOutcome.Conflict, stale.Outcome);
        Assert.Equal(0, stale.Revision);

        var relaunch = await _store.UpsertAsync(account, 0, b, SHA256.HashData(b));
        Assert.Equal(4, relaunch.Revision);

        // Device B still remembers revision 1: the new lineage never reuses it, so B conflicts.
        var deviceB = await _store.UpsertAsync(account, 1, a, SHA256.HashData(a));
        Assert.Equal(EnvelopeUpsertOutcome.Conflict, deviceB.Outcome);
        Assert.Equal(4, deviceB.Revision);
        var status = await _store.GetAsync(account, includeEnvelope: false);
        Assert.Equal(4, status!.Revision);
        Assert.Equal(SHA256.HashData(b), status.Fingerprint);
    }

    [Fact]
    public async Task ReadTimestamps_AreUtc()
    {
        var account = await NewAccountAsync();
        var envelope = Bytes("{\"version\":1}");
        await _store.UpsertAsync(account, 0, envelope, SHA256.HashData(envelope));

        var stored = await _store.GetAsync(account, includeEnvelope: false);
        Assert.Equal(DateTimeKind.Utc, stored!.UpdatedAt.Kind);
        Assert.Equal(DateTimeKind.Utc, stored.CreatedAt.Kind);
        Assert.Equal(_clock.GetUtcNow().UtcDateTime, stored.UpdatedAt);
    }

    [Fact]
    public async Task AnEnvelopeOfExactly16MiB_RoundTrips()
    {
        var account = await NewAccountAsync();
        const int size = 16 * 1024 * 1024; // the API limit, one byte more than MEDIUMBLOB holds
        var prefix = Bytes("{\"version\":1,\"ciphertext\":\"");
        var suffix = Bytes("\"}");
        var envelope = new byte[size];
        prefix.CopyTo(envelope, 0);
        envelope.AsSpan(prefix.Length, size - prefix.Length - suffix.Length).Fill((byte)'x');
        suffix.CopyTo(envelope, size - suffix.Length);

        var result = await _store.UpsertAsync(account, 0, envelope, SHA256.HashData(envelope));

        Assert.Equal(EnvelopeUpsertOutcome.Stored, result.Outcome);
        var stored = await _store.GetAsync(account, includeEnvelope: true);
        Assert.Equal(size, stored!.SizeBytes);
        Assert.Equal(SHA256.HashData(envelope), SHA256.HashData(stored.Envelope!));
    }

    [Fact]
    public async Task DeletingTheAccount_TakesTheEnvelopeWithIt()
    {
        var account = await NewAccountAsync();
        var envelope = Bytes("{\"version\":1}");
        await _store.UpsertAsync(account, 0, envelope, SHA256.HashData(envelope));

        await using (var connection = await _fixture.ConnectionFactory.OpenConnectionAsync())
        {
            await using var command = connection.CreateCommand();
            command.CommandText = "DELETE FROM accounts WHERE id = @id;";
            command.Parameters.AddWithValue("@id", account);
            await command.ExecuteNonQueryAsync();
        }

        Assert.Null(await _store.GetAsync(account, includeEnvelope: true));
    }

    [Fact]
    public async Task ALargeEnvelope_RoundTrips()
    {
        var account = await NewAccountAsync();
        var body = new string('x', 1024 * 1024); // 1 MiB of payload; the ceiling is a host setting, not a store rule
        var envelope = Bytes("{\"version\":1,\"ciphertext\":\"" + body + "\"}");

        var result = await _store.UpsertAsync(account, 0, envelope, SHA256.HashData(envelope));

        Assert.Equal(EnvelopeUpsertOutcome.Stored, result.Outcome);
        var stored = await _store.GetAsync(account, includeEnvelope: true);
        Assert.Equal(envelope.Length, stored!.SizeBytes);
        Assert.Equal(envelope, stored.Envelope);
    }

    [Fact]
    public async Task TheStore_RefusesImpossibleArguments()
    {
        var account = await NewAccountAsync();
        await Assert.ThrowsAsync<ArgumentException>(() => _store.UpsertAsync(account, 0, [], new byte[32]));
        await Assert.ThrowsAsync<ArgumentException>(() => _store.UpsertAsync(account, 0, Bytes("{}"), new byte[31]));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => _store.UpsertAsync(account, -1, Bytes("{}"), new byte[32]));
    }
}

[Collection("Persistence")]
public sealed class Migration0003Tests
{
    private readonly DatabaseFixture _fixture;

    public Migration0003Tests(DatabaseFixture fixture) => _fixture = fixture;

    [Fact]
    public async Task Migration0003_IsRecorded()
        => Assert.Contains("0003_vault_sync.sql", await _fixture.GetRecordedMigrationsAsync());

    [Fact]
    public async Task VaultBlobsTable_Exists()
        => Assert.True(await _fixture.TableExistsAsync("vault_blobs"));

    [Fact]
    public async Task Migration0006_MakesTheEnvelopeANullableLongBlob()
    {
        Assert.Contains("0006_vault_revision_tombstone_longblob.sql", await _fixture.GetRecordedMigrationsAsync());
        await using var connection = await _fixture.ConnectionFactory.OpenConnectionAsync();
        await using var command = connection.CreateCommand();
        command.CommandText =
            "SELECT DATA_TYPE, IS_NULLABLE FROM information_schema.columns " +
            "WHERE table_schema = DATABASE() AND table_name = 'vault_blobs' AND column_name = 'envelope';";
        await using var reader = await command.ExecuteReaderAsync();
        Assert.True(await reader.ReadAsync());
        Assert.Equal("longblob", reader.GetString(0), ignoreCase: true);
        Assert.Equal("YES", reader.GetString(1));
    }
}
