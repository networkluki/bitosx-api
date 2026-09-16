using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using BitosX.Application.Email;

namespace BitosX.Infrastructure.Email;

/// <summary>
/// AES-256-GCM protection for outbox payloads. Uses a fresh 96-bit random nonce
/// per call and a 128-bit tag. The AAD binds (id, version, message_type,
/// recipient_email) via a canonical length-prefixed encoding — no ambiguous
/// concatenation — so tampering with any of those row fields fails
/// authentication. Never logs the key or plaintext.
/// </summary>
public sealed class AesGcmOutboxPayloadProtector : IOutboxPayloadProtector
{
    private const int NonceBytes = 12;
    private const int TagBytes = 16;
    private const byte EnvelopeVersion = 1;

    private readonly byte[] _key;

    public AesGcmOutboxPayloadProtector(EmailOutboxCryptoOptions options)
    {
        if (string.IsNullOrEmpty(options.Key))
        {
            throw new InvalidOperationException("EmailOutboxKey is not configured.");
        }

        byte[] key;
        try
        {
            key = Convert.FromBase64String(options.Key);
        }
        catch (FormatException)
        {
            throw new InvalidOperationException("EmailOutboxKey must be Base64.");
        }

        if (key.Length != 32)
        {
            throw new InvalidOperationException("EmailOutboxKey must decode to 32 bytes (AES-256).");
        }

        _key = key;
    }

    public ProtectedOutboxPayload Protect(OutboxPayload payload, OutboxAad aad)
    {
        var plaintext = JsonSerializer.SerializeToUtf8Bytes(payload);
        var nonce = RandomNumberGenerator.GetBytes(NonceBytes);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[TagBytes];
        var associatedData = EncodeAad(aad);

        using var gcm = new AesGcm(_key, TagBytes);
        gcm.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);

        return new ProtectedOutboxPayload(EnvelopeVersion, nonce, ciphertext, tag);
    }

    public bool TryUnprotect(ProtectedOutboxPayload protectedPayload, OutboxAad aad, out OutboxPayload? payload)
    {
        payload = null;
        if (protectedPayload.Version != EnvelopeVersion
            || protectedPayload.Nonce.Length != NonceBytes
            || protectedPayload.Tag.Length != TagBytes)
        {
            return false;
        }

        var plaintext = new byte[protectedPayload.Ciphertext.Length];
        var associatedData = EncodeAad(aad);

        try
        {
            using var gcm = new AesGcm(_key, TagBytes);
            gcm.Decrypt(protectedPayload.Nonce, protectedPayload.Ciphertext, protectedPayload.Tag, plaintext, associatedData);
        }
        catch (CryptographicException)
        {
            return false; // authentication failure (wrong key / tampered ct/tag/nonce / AAD mismatch)
        }

        try
        {
            payload = JsonSerializer.Deserialize<OutboxPayload>(plaintext);
        }
        catch (JsonException)
        {
            payload = null;
            return false;
        }

        return payload is not null;
    }

    /// <summary>Canonical AAD: for each field, uint32 big-endian length prefix || UTF-8 bytes, fixed order.</summary>
    private static byte[] EncodeAad(OutboxAad aad)
    {
        using var ms = new MemoryStream();
        WriteField(ms, Encoding.UTF8.GetBytes(aad.Id.ToString("D")));
        WriteField(ms, [aad.Version]);
        WriteField(ms, Encoding.UTF8.GetBytes(aad.MessageType));
        WriteField(ms, Encoding.UTF8.GetBytes(aad.RecipientEmail));
        return ms.ToArray();
    }

    private static void WriteField(Stream stream, byte[] field)
    {
        Span<byte> lengthPrefix = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(lengthPrefix, (uint)field.Length);
        stream.Write(lengthPrefix);
        stream.Write(field);
    }
}
