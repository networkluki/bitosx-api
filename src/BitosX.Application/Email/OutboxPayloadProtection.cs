namespace BitosX.Application.Email;

/// <summary>Decrypted outbox payload. Carries the raw verification token transiently for delivery.</summary>
public sealed record OutboxPayload(
    int Version,
    Guid AccountId,
    string TokenBase64Url,
    DateTime ExpiresAtUtc,
    string ToAddress);

/// <summary>Encrypted-at-rest outbox payload (AES-256-GCM).</summary>
public sealed record ProtectedOutboxPayload(byte Version, byte[] Nonce, byte[] Ciphertext, byte[] Tag);

/// <summary>
/// Associated data authenticated (not encrypted) alongside the payload. Binds
/// the ciphertext to its outbox row so a DB-write attacker cannot re-target or
/// transplant it. Encoded canonically (length-prefixed) by the protector.
/// </summary>
public sealed record OutboxAad(Guid Id, byte Version, string MessageType, string RecipientEmail);

/// <summary>Server secret for outbox payload encryption (independent of pepper/vault/password hashing).</summary>
public sealed class EmailOutboxCryptoOptions
{
    /// <summary>Base64-encoded 256-bit AES key. Secret; never committed.</summary>
    public string Key { get; set; } = string.Empty;
}

/// <summary>Authenticated encryption for outbox verification-token payloads.</summary>
public interface IOutboxPayloadProtector
{
    ProtectedOutboxPayload Protect(OutboxPayload payload, OutboxAad aad);

    /// <summary>Returns false (no throw) if decryption/authentication fails.</summary>
    bool TryUnprotect(ProtectedOutboxPayload protectedPayload, OutboxAad aad, out OutboxPayload? payload);
}
