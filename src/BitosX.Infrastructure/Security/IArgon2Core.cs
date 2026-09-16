namespace BitosX.Infrastructure.Security;

/// <summary>
/// The raw Argon2id key-derivation primitive. Isolated behind an interface so
/// tests can assert it is NEVER invoked for hostile/out-of-bounds hashes.
/// </summary>
public interface IArgon2Core
{
    byte[] Compute(byte[] password, byte[] salt, int memoryKiB, int iterations, int lanes, int outputLength);
}
