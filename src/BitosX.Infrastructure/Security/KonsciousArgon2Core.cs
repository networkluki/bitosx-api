using System.Text;
using Konscious.Security.Cryptography;

namespace BitosX.Infrastructure.Security;

/// <summary>Argon2id via Konscious. Password bytes are UTF-8 of the exact input string.</summary>
public sealed class KonsciousArgon2Core : IArgon2Core
{
    public byte[] Compute(byte[] password, byte[] salt, int memoryKiB, int iterations, int lanes, int outputLength)
    {
        using var argon2 = new Argon2id(password)
        {
            Salt = salt,
            MemorySize = memoryKiB,
            Iterations = iterations,
            DegreeOfParallelism = lanes,
        };
        return argon2.GetBytes(outputLength);
    }

    internal static byte[] PasswordBytes(string password) => Encoding.UTF8.GetBytes(password);
}
