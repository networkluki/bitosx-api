using System.Security.Cryptography;
using System.Text;
using BitosX.Application.Security;

namespace BitosX.Infrastructure.Security;

/// <summary>
/// Argon2id account-password hasher. Produces/consumes self-describing PHC
/// strings. Verification validates encoded parameters against configured
/// resource ceilings BEFORE invoking Argon2, so a hostile stored hash cannot
/// force high-cost work. A concurrency gate bounds simultaneous hashing memory.
/// </summary>
public sealed class Argon2idPasswordHasher : IAccountPasswordHasher
{
    private const int SaltBytes = 16;
    private const int HashBytes = 32;

    private readonly Argon2ParametersOptions _options;
    private readonly IArgon2Core _core;
    private readonly Argon2WorkGate _gate;

    public Argon2idPasswordHasher(Argon2ParametersOptions options, IArgon2Core core, Argon2WorkGate gate)
    {
        _options = options;
        _core = core;
        _gate = gate;
    }

    public async Task<string> HashAsync(string password, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(password);

        var salt = RandomNumberGenerator.GetBytes(SaltBytes);
        var passwordBytes = Encoding.UTF8.GetBytes(password);

        var hash = await ComputeAsync(passwordBytes, salt, _options.MemoryKiB, _options.Iterations, _options.Lanes, HashBytes, cancellationToken).ConfigureAwait(false);
        return Argon2PhcString.Encode(_options.MemoryKiB, _options.Iterations, _options.Lanes, salt, hash);
    }

    public async Task<PasswordVerificationResult> VerifyAsync(string password, string encodedHash, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(password);

        // (1) Structural parse + static hard bounds — no Argon2, no large alloc, no gate admission.
        if (!Argon2PhcString.TryParse(encodedHash, out var phc) || phc is null)
        {
            return PasswordVerificationResult.InvalidHashFormat;
        }

        // (2) Configurable resource ceilings (budget-derived) — still before Argon2.
        if (phc.Lanes != _options.Lanes
            || phc.MemoryKiB > _options.EffectiveMaxVerifyMemoryKiB()
            || phc.MemoryKiB < Argon2ParametersOptions.AbsoluteMinMemoryKiB
            || phc.Iterations > _options.EffectiveMaxVerifyIterations()
            || phc.Iterations < 1)
        {
            return PasswordVerificationResult.InvalidHashFormat;
        }

        // (3) Only now do we admit + run the (bounded) KDF.
        var passwordBytes = Encoding.UTF8.GetBytes(password);
        var computed = await ComputeAsync(passwordBytes, phc.Salt, phc.MemoryKiB, phc.Iterations, phc.Lanes, phc.Hash.Length, cancellationToken).ConfigureAwait(false);

        if (!CryptographicOperations.FixedTimeEquals(computed, phc.Hash))
        {
            return PasswordVerificationResult.Failed;
        }

        var weaker = phc.MemoryKiB < _options.MemoryKiB || phc.Iterations < _options.Iterations;
        return weaker ? PasswordVerificationResult.NeedsRehash : PasswordVerificationResult.Success;
    }

    private async Task<byte[]> ComputeAsync(byte[] password, byte[] salt, int memoryKiB, int iterations, int lanes, int outputLength, CancellationToken cancellationToken)
    {
        // Bounded admission: throws PasswordHashingCapacityExceededException on saturation/timeout;
        // propagates OperationCanceledException on genuine cancellation. The lease releases exactly once.
        using var permit = await _gate.AcquireAsync(cancellationToken).ConfigureAwait(false);
        return _core.Compute(password, salt, memoryKiB, iterations, lanes, outputLength);
    }
}
