using System.Security.Cryptography;
using System.Text;
using BitosX.Application.Abstractions.Persistence;
using BitosX.Application.Sync;

namespace BitosX.Application.Tests;

/// <summary>
/// The sync service over a fake store: what it refuses before touching the store (size, shape), the
/// fingerprint it computes, and how store outcomes map. The shape check must accept every real
/// envelope and refuse everything that is not one, without decoding a single cryptographic field.
/// </summary>
public sealed class VaultSyncServiceTests
{
    private static readonly Guid Account = Guid.NewGuid();

    // The real on-disk format (format v1) with placeholder Base64 — see bitosx/docs/CRYPTOGRAPHY.md.
    private const string Envelope = """
        {"version":1,"kdf":"argon2id","kdfParameters":{"memoryKiB":262144,"iterations":3,"parallelism":4,"keyLengthBytes":32},
         "salt":"AAAAAAAAAAAAAAAAAAAAAA==","algorithm":"AES-256-GCM","keyWrapNonce":"AAAAAAAAAAAAAAAA",
         "encryptedVaultKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","contentNonce":"AAAAAAAAAAAAAAAA","ciphertext":"AAAA"}
        """;

    private sealed class FakeStore : IEnvelopeStore
    {
        public long CurrentRevision { get; set; }
        public bool AccountExists { get; set; } = true;
        public (Guid AccountId, long BaseRevision, byte[] Envelope, byte[] Fingerprint)? LastUpsert { get; private set; }
        public int DeleteCount { get; private set; }
        public StoredEnvelope? Stored { get; set; }

        public Task<StoredEnvelope?> GetAsync(Guid accountId, bool includeEnvelope, CancellationToken cancellationToken = default)
            => Task.FromResult(Stored is null ? null : includeEnvelope ? Stored : Stored with { Envelope = null });

        public Task<EnvelopeUpsertResult> UpsertAsync(Guid accountId, long baseRevision, byte[] envelope, byte[] fingerprint, CancellationToken cancellationToken = default)
        {
            LastUpsert = (accountId, baseRevision, envelope, fingerprint);
            if (!AccountExists) return Task.FromResult(new EnvelopeUpsertResult(EnvelopeUpsertOutcome.NoAccount, 0, default));
            if (baseRevision != CurrentRevision) return Task.FromResult(new EnvelopeUpsertResult(EnvelopeUpsertOutcome.Conflict, CurrentRevision, DateTime.UtcNow));
            CurrentRevision++;
            return Task.FromResult(new EnvelopeUpsertResult(EnvelopeUpsertOutcome.Stored, CurrentRevision, DateTime.UtcNow));
        }

        public Task<bool> DeleteAsync(Guid accountId, CancellationToken cancellationToken = default)
        {
            DeleteCount++;
            return Task.FromResult(true);
        }
    }

    private static (VaultSyncService Service, FakeStore Store) New(int maxBytes = VaultSyncOptions.DefaultMaxEnvelopeBytes)
    {
        var store = new FakeStore();
        return (new VaultSyncService(store, new VaultSyncOptions { MaxEnvelopeBytes = maxBytes }), store);
    }

    [Fact]
    public async Task Upload_StoresTheBytesAsGiven_WithTheirSha256()
    {
        var (service, store) = New();
        var bytes = Encoding.UTF8.GetBytes(Envelope);

        var result = await service.UploadAsync(Account, 0, bytes);

        Assert.Equal(SyncUploadOutcome.Stored, result.Outcome);
        Assert.Equal(1, result.Revision);
        Assert.Equal(SHA256.HashData(bytes), result.Fingerprint);
        Assert.Equal(bytes.Length, result.SizeBytes);
        Assert.NotNull(store.LastUpsert);
        Assert.Equal(bytes, store.LastUpsert!.Value.Envelope);          // byte for byte, no re-serialization
        Assert.Equal(SHA256.HashData(bytes), store.LastUpsert.Value.Fingerprint);
    }

    [Fact]
    public async Task Upload_AgainstAStaleRevision_IsAConflict_AndNothingIsWritten()
    {
        var (service, store) = New();
        store.CurrentRevision = 4;

        var result = await service.UploadAsync(Account, 2, Encoding.UTF8.GetBytes(Envelope));

        Assert.Equal(SyncUploadOutcome.Conflict, result.Outcome);
        Assert.Equal(4, result.Revision);
        Assert.Null(result.Fingerprint);
        Assert.Equal(4, store.CurrentRevision);
    }

    [Fact]
    public async Task Upload_ForAVanishedAccount_IsRefused()
    {
        var (service, store) = New();
        store.AccountExists = false;

        var result = await service.UploadAsync(Account, 0, Encoding.UTF8.GetBytes(Envelope));

        Assert.Equal(SyncUploadOutcome.NoAccount, result.Outcome);
    }

    [Fact]
    public async Task Upload_BeyondTheLimit_NeverReachesTheStore()
    {
        var (service, store) = New(maxBytes: 1024);
        var big = Encoding.UTF8.GetBytes("{\"version\":1,\"pad\":\"" + new string('x', 2000) + "\"}");

        var result = await service.UploadAsync(Account, 0, big);

        Assert.Equal(SyncUploadOutcome.TooLarge, result.Outcome);
        Assert.Null(store.LastUpsert);
    }

    [Theory]
    [InlineData("")]
    [InlineData("not json")]
    [InlineData("[1,2,3]")]
    [InlineData("\"a string\"")]
    [InlineData("{}")]                                     // no version
    [InlineData("{\"version\":\"1\"}")]                     // version not a number
    [InlineData("{\"version\":0}")]
    [InlineData("{\"version\":-1}")]
    [InlineData("{\"version\":1.5}")]
    [InlineData("{\"version\":1} trailing")]
    [InlineData("{\"version\":1}{\"version\":1}")]
    [InlineData("{\"nested\":{\"version\":1}}")]           // version must be top level
    [InlineData("{\"version\":1,\"a\":{\"b\":{\"c\":{\"d\":{\"e\":1}}}}}")] // deeper than any envelope
    public async Task Upload_OfSomethingThatIsNotAnEnvelope_IsRefused_BeforeTheStore(string text)
    {
        var (service, store) = New();

        var result = await service.UploadAsync(Account, 0, Encoding.UTF8.GetBytes(text));

        Assert.Equal(SyncUploadOutcome.InvalidEnvelope, result.Outcome);
        Assert.Null(store.LastUpsert);
    }

    [Fact]
    public async Task Upload_OfInvalidUtf8_IsRefused()
    {
        var (service, store) = New();

        var result = await service.UploadAsync(Account, 0, [0x7B, 0xC3, 0x28, 0x7D]);

        Assert.Equal(SyncUploadOutcome.InvalidEnvelope, result.Outcome);
        Assert.Null(store.LastUpsert);
    }

    [Theory]
    [InlineData("{\"version\":1}")]
    [InlineData("{\"kdf\":\"argon2id\",\"version\":2}")]
    [InlineData(" {\"version\":1} ")]
    public void LooksLikeEnvelope_AcceptsAnyObjectWithAPositiveIntegerVersion(string text)
        => Assert.True(VaultSyncService.LooksLikeEnvelope(Encoding.UTF8.GetBytes(text)));

    [Fact]
    public void LooksLikeEnvelope_AcceptsTheRealFormat()
        => Assert.True(VaultSyncService.LooksLikeEnvelope(Encoding.UTF8.GetBytes(Envelope)));

    [Fact]
    public async Task Upload_RejectsImpossibleArguments()
    {
        var (service, _) = New();
        await Assert.ThrowsAsync<ArgumentException>(() => service.UploadAsync(Guid.Empty, 0, Encoding.UTF8.GetBytes(Envelope)));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => service.UploadAsync(Account, -1, Encoding.UTF8.GetBytes(Envelope)));
        await Assert.ThrowsAsync<ArgumentNullException>(() => service.UploadAsync(Account, 0, null!));
    }

    [Fact]
    public async Task Status_CarriesNoBytes_Download_Does()
    {
        var (service, store) = New();
        var bytes = Encoding.UTF8.GetBytes(Envelope);
        store.Stored = new StoredEnvelope(Account, 3, SHA256.HashData(bytes), bytes.Length, DateTime.UtcNow, DateTime.UtcNow, bytes);

        var status = await service.GetStatusAsync(Account);
        var download = await service.DownloadAsync(Account);

        Assert.NotNull(status);
        Assert.Null(status!.Envelope);
        Assert.Equal(3, status.Revision);
        Assert.Equal(bytes, download!.Envelope);
    }

    [Fact]
    public async Task Delete_GoesToTheStore()
    {
        var (service, store) = New();
        await service.DeleteAsync(Account);
        Assert.Equal(1, store.DeleteCount);
    }

    [Theory]
    [InlineData(1023)]
    [InlineData(VaultSyncOptions.DefaultMaxEnvelopeBytes + 1)]
    [InlineData(0)]
    [InlineData(-1)]
    public void Options_OutOfRange_FailClosed(int maxBytes)
        => Assert.Throws<InvalidOperationException>(() => new VaultSyncOptions { MaxEnvelopeBytes = maxBytes }.Validate());

    [Fact]
    public void Options_BodyLimit_CoversTheBase64OfTheLargestEnvelope()
    {
        var options = new VaultSyncOptions { MaxEnvelopeBytes = 16 * 1024 * 1024 };
        var base64Length = ((long)options.MaxEnvelopeBytes + 2) / 3 * 4;
        Assert.True(options.MaxUploadBodyBytes > base64Length);
        Assert.True(options.MaxUploadBodyBytes < base64Length + 4096);
    }
}
