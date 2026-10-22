using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using BitosX.Application.Mfa;

namespace BitosX.Infrastructure.Security;

/// <summary>Server secret for the second factor (independent of pepper/outbox/JWT/vault keys).</summary>
public sealed class TotpCryptoOptions
{
    /// <summary>Base64-encoded 256-bit master key. Secret; never committed.</summary>
    public string Key { get; set; } = string.Empty;
}

/// <summary>
/// AES-256-GCM for TOTP secrets at rest and HMAC-SHA256 for recovery-code verifiers, both under keys
/// derived with HKDF-SHA256 from <c>Security:TotpKey</c> (distinct labels, so neither use can be
/// swapped for the other). The AAD binds a secret to its account id and envelope version.
/// </summary>
public sealed class AesGcmTotpCrypto : ITotpCrypto
{
    private const int NonceBytes = 12;
    private const int TagBytes = 16;
    private const byte EnvelopeVersion = 1;

    private readonly byte[] _secretKey;
    private readonly byte[] _recoveryKey;

    public AesGcmTotpCrypto(TotpCryptoOptions options)
    {
        if (string.IsNullOrEmpty(options.Key))
        {
            throw new InvalidOperationException("TotpKey is not configured.");
        }

        byte[] master;
        try
        {
            master = Convert.FromBase64String(options.Key);
        }
        catch (FormatException)
        {
            throw new InvalidOperationException("Security:TotpKey must be Base64.");
        }

        if (master.Length != 32)
        {
            throw new InvalidOperationException("Security:TotpKey must decode to 32 bytes (AES-256).");
        }

        _secretKey = HKDF.DeriveKey(HashAlgorithmName.SHA256, master, 32, info: "BitosX|totp|secret|v1"u8.ToArray());
        _recoveryKey = HKDF.DeriveKey(HashAlgorithmName.SHA256, master, 32, info: "BitosX|totp|recovery|v1"u8.ToArray());
        CryptographicOperations.ZeroMemory(master);
    }

    public ProtectedTotpSecret Protect(ReadOnlySpan<byte> secret, Guid accountId)
    {
        var nonce = RandomNumberGenerator.GetBytes(NonceBytes);
        var ciphertext = new byte[secret.Length];
        var tag = new byte[TagBytes];
        using var gcm = new AesGcm(_secretKey, TagBytes);
        gcm.Encrypt(nonce, secret, ciphertext, tag, Aad(accountId, EnvelopeVersion));
        return new ProtectedTotpSecret(EnvelopeVersion, nonce, ciphertext, tag);
    }

    public bool TryUnprotect(ProtectedTotpSecret protectedSecret, Guid accountId, out byte[] secret)
    {
        secret = [];
        if (protectedSecret.Version != EnvelopeVersion || protectedSecret.Nonce.Length != NonceBytes || protectedSecret.Tag.Length != TagBytes)
        {
            return false;
        }

        var plaintext = new byte[protectedSecret.Ciphertext.Length];
        try
        {
            using var gcm = new AesGcm(_secretKey, TagBytes);
            gcm.Decrypt(protectedSecret.Nonce, protectedSecret.Ciphertext, protectedSecret.Tag, plaintext, Aad(accountId, protectedSecret.Version));
        }
        catch (CryptographicException)
        {
            return false;
        }

        secret = plaintext;
        return true;
    }

    public byte[] RecoveryCodeVerifier(string canonicalCode)
        => HMACSHA256.HashData(_recoveryKey, Encoding.ASCII.GetBytes(canonicalCode));

    private static byte[] Aad(Guid accountId, byte version)
    {
        var id = Encoding.UTF8.GetBytes(accountId.ToString("D"));
        var aad = new byte[4 + id.Length + 4 + 1];
        BinaryPrimitives.WriteUInt32BigEndian(aad, (uint)id.Length);
        id.CopyTo(aad, 4);
        BinaryPrimitives.WriteUInt32BigEndian(aad.AsSpan(4 + id.Length), 1);
        aad[^1] = version;
        return aad;
    }
}
