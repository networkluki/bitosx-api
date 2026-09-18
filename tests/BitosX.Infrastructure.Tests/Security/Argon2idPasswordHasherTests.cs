using System.Security.Cryptography;
using BitosX.Application.Security;
using BitosX.Infrastructure.Security;

namespace BitosX.Infrastructure.Tests.Security;

/// <summary>Counting Argon2 core: proves the KDF is (not) invoked and enables fast tests.</summary>
internal sealed class CountingArgon2Core : IArgon2Core
{
    public int Calls { get; private set; }

    public byte[] Compute(byte[] password, byte[] salt, int memoryKiB, int iterations, int lanes, int outputLength)
    {
        Calls++;
        // Deterministic dummy output derived from inputs (no real Argon2 cost).
        using var sha = SHA256.Create();
        var seed = sha.ComputeHash([.. password, .. salt]);
        var outBytes = new byte[outputLength];
        Array.Copy(seed, outBytes, Math.Min(seed.Length, outputLength));
        return outBytes;
    }
}

public sealed class Argon2idPasswordHasherTests
{
    // Small real params keep the round-trip tests fast while staying within bounds.
    private static Argon2ParametersOptions FastOptions() => new()
    {
        MemoryKiB = 8192, // 8 MiB (== absolute floor)
        Iterations = 1,
        Lanes = 1,
        MaxConcurrency = 2,
    };

    private static Argon2WorkGate Gate() => new(new Argon2AdmissionOptions());

    private static Argon2idPasswordHasher RealHasher(Argon2ParametersOptions? o = null)
        => new(o ?? FastOptions(), new KonsciousArgon2Core(), Gate());

    [Fact]
    public async Task Hash_ProducesArgon2idPhc_AndVerifies()
    {
        var hasher = RealHasher();
        var hash = await hasher.HashAsync("correct horse battery staple");
        Assert.StartsWith("$argon2id$v=19$", hash);
        Assert.Equal(PasswordVerificationResult.Success, await hasher.VerifyAsync("correct horse battery staple", hash));
    }

    [Fact]
    public async Task Verify_WrongPassword_Fails()
    {
        var hasher = RealHasher();
        var hash = await hasher.HashAsync("the-right-password");
        Assert.Equal(PasswordVerificationResult.Failed, await hasher.VerifyAsync("the-wrong-password", hash));
    }

    [Fact]
    public async Task Hash_SamePassword_DiffersBySalt()
    {
        var hasher = RealHasher();
        Assert.NotEqual(await hasher.HashAsync("same-password-123"), await hasher.HashAsync("same-password-123"));
    }

    [Fact]
    public async Task Verify_GarbageHash_IsInvalidFormat()
    {
        var hasher = RealHasher();
        Assert.Equal(PasswordVerificationResult.InvalidHashFormat, await hasher.VerifyAsync("pw", "not-a-valid-hash"));
    }

    [Fact]
    public async Task Verify_WeakerStoredParams_NeedsRehash()
    {
        // Stored at 8 MiB / t=1; current policy wants more → NeedsRehash on correct password.
        var weak = RealHasher(new Argon2ParametersOptions { MemoryKiB = 8192, Iterations = 1, Lanes = 1, MaxConcurrency = 2 });
        var stored = await weak.HashAsync("upgrade-me-please");

        var current = RealHasher(new Argon2ParametersOptions { MemoryKiB = 16384, Iterations = 2, Lanes = 1, MaxConcurrency = 2 });
        Assert.Equal(PasswordVerificationResult.NeedsRehash, await current.VerifyAsync("upgrade-me-please", stored));
    }

    // ---- Resource-exhaustion guard: KDF must NOT run for hostile hashes ----

    [Theory]
    [InlineData("$argon2id$v=19$m=9999999999,t=3,p=1$YWJjZGVmZ2g$YWJjZGVmZ2hpamtsbW5vcA")] // overflow m
    [InlineData("$argon2id$v=19$m=47104,t=999,p=1$YWJjZGVmZ2g$YWJjZGVmZ2hpamtsbW5vcA")]     // t above cap
    [InlineData("$argon2id$v=19$m=47104,t=3,p=2$YWJjZGVmZ2g$YWJjZGVmZ2hpamtsbW5vcA")]       // p != 1
    [InlineData("garbage")]
    public async Task Verify_HostileHash_NeverInvokesKdf(string hostile)
    {
        var spy = new CountingArgon2Core();
        var hasher = new Argon2idPasswordHasher(FastOptions(), spy, Gate());

        Assert.Equal(PasswordVerificationResult.InvalidHashFormat, await hasher.VerifyAsync("pw", hostile));
        Assert.Equal(0, spy.Calls);
    }

    [Fact]
    public async Task Verify_MemoryAboveConfiguredCeiling_RejectedWithoutKdf()
    {
        var options = FastOptions(); // MaxConcurrency=2 → per-slot budget 96 MiB (98304 KiB)
        var spy = new CountingArgon2Core();
        var hasher = new Argon2idPasswordHasher(options, spy, Gate());

        // m = 192 MiB passes STATIC structural bounds but exceeds the config ceiling.
        var overBudget = Argon2PhcString.Encode(192 * 1024, 3, 1,
            RandomNumberGenerator.GetBytes(16), RandomNumberGenerator.GetBytes(32));

        Assert.True(overBudget.Length <= Argon2PhcString.MaxEncodedLength);
        Assert.Equal(PasswordVerificationResult.InvalidHashFormat, await hasher.VerifyAsync("pw", overBudget));
        Assert.Equal(0, spy.Calls);
    }

    [Fact]
    public async Task Verify_InBoundsHash_DoesInvokeKdf()
    {
        // Control: a well-formed in-bounds hash reaches the KDF exactly once.
        var spy = new CountingArgon2Core();
        var hasher = new Argon2idPasswordHasher(FastOptions(), spy, Gate());
        var inBounds = Argon2PhcString.Encode(8192, 1, 1,
            RandomNumberGenerator.GetBytes(16), RandomNumberGenerator.GetBytes(32));

        await hasher.VerifyAsync("pw", inBounds);
        Assert.Equal(1, spy.Calls);
    }
}
