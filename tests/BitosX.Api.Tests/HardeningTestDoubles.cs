using System.Security.Cryptography;
using BitosX.Api.Security;
using BitosX.Infrastructure.Security;

namespace BitosX.Api.Tests;

/// <summary>
/// Test Argon2 core that can hold the caller inside Compute (holding the admission permit) until released,
/// signalling when it is entered. Starts UNBLOCKED so account setup (verify-email hashing) completes; call
/// <see cref="Arm"/> to make the next Compute block. Deterministic overload choreography, no sleeps.
/// </summary>
internal sealed class BlockingArgon2Core : IArgon2Core
{
    private readonly ManualResetEventSlim _release = new(initialState: true);
    private volatile TaskCompletionSource _entered = new(TaskCreationOptions.RunContinuationsAsynchronously);

    /// <summary>Completes when a Compute call has entered (the permit is held).</summary>
    public Task Entered => _entered.Task;

    /// <summary>Arms a fresh "entered" signal and blocks the next Compute until <see cref="Release"/>.</summary>
    public void Arm()
    {
        _entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        _release.Reset();
    }

    public void Release() => _release.Set();

    public byte[] Compute(byte[] password, byte[] salt, int memoryKiB, int iterations, int lanes, int outputLength)
    {
        _entered.TrySetResult();
        _release.Wait();
        // Deterministic, input-derived output (no real Argon2 cost) so correct vs wrong passwords differ.
        var seed = SHA256.HashData([.. password, .. salt]);
        var outBytes = new byte[outputLength];
        Array.Copy(seed, outBytes, Math.Min(seed.Length, outputLength));
        return outBytes;
    }
}

/// <summary>Records how many times login-response jitter was applied (used to prove which outcomes jitter).</summary>
internal sealed class RecordingLoginResponseJitter : ILoginResponseJitter
{
    private int _calls;
    public int Calls => Volatile.Read(ref _calls);

    public Task ApplyAsync(CancellationToken cancellationToken)
    {
        Interlocked.Increment(ref _calls);
        return Task.CompletedTask;
    }
}
