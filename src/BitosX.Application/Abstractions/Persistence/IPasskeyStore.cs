namespace BitosX.Application.Abstractions.Persistence;

/// <summary>
/// A registered passkey (WebAuthn public-key credential) of an account. <see cref="PublicKey"/> is the COSE public key
/// the authenticator returned at registration; nothing secret is stored. <see cref="UserHandle"/> is the account's
/// random WebAuthn user handle at registration time (never the account id or the email).
/// </summary>
public sealed record StoredPasskey(
    Guid Id,
    Guid AccountId,
    byte[] CredentialId,
    byte[] PublicKey,
    long SignCount,
    byte[] UserHandle,
    string Name,
    Guid AaGuid,
    bool BackupEligible,
    bool BackedUp,
    string? Transports,
    DateTime CreatedAt,
    DateTime? LastUsedAt)
{
    public override string ToString() => $"StoredPasskey {{ Id = {Id}, AccountId = {AccountId}, Name = <redacted>, CredentialId = <redacted> }}";
}

public enum PasskeyInsertOutcome
{
    Inserted,

    /// <summary>The account no longer has TOTP confirmed (passkeys are added on top of TOTP, never instead of it).</summary>
    TwoFactorRequired,

    /// <summary>The account already has the maximum number of passkeys.</summary>
    LimitReached,

    /// <summary>The credential id is already registered (to this or any other account).</summary>
    DuplicateCredential,
}

/// <summary>
/// Persistence for passkeys: the per-account WebAuthn user handle and the registered credentials. Composed with
/// Login (DB only), like the TOTP store, so the login and TOTP paths can see that passkeys exist even when the
/// Passkeys capability is off.
/// </summary>
public interface IPasskeyStore
{
    /// <summary>The account's WebAuthn user handle; assigns <paramref name="candidate"/> first when it has none. Null when the account does not exist.</summary>
    Task<byte[]?> GetOrAssignUserHandleAsync(Guid accountId, byte[] candidate, CancellationToken cancellationToken = default);

    /// <summary>The account's WebAuthn user handle, or null when none was assigned yet.</summary>
    Task<byte[]?> GetUserHandleAsync(Guid accountId, CancellationToken cancellationToken = default);

    /// <summary>The account's passkeys, oldest first.</summary>
    Task<IReadOnlyList<StoredPasskey>> ListAsync(Guid accountId, CancellationToken cancellationToken = default);

    Task<int> CountAsync(Guid accountId, CancellationToken cancellationToken = default);

    /// <summary>The passkey with this credential id (whatever account owns it), or null.</summary>
    Task<StoredPasskey?> FindByCredentialIdAsync(byte[] credentialId, CancellationToken cancellationToken = default);

    Task<bool> CredentialIdExistsAsync(byte[] credentialId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Inserts a new passkey in one transaction that locks the account row and then its TOTP row (the order TOTP
    /// enrollment uses), and re-checks there that TOTP is confirmed and fewer than <paramref name="maxPerAccount"/>
    /// passkeys exist, so neither a concurrent TOTP disable nor concurrent registrations can get past the rules.
    /// </summary>
    Task<PasskeyInsertOutcome> InsertAsync(StoredPasskey passkey, int maxPerAccount, CancellationToken cancellationToken = default);

    /// <summary>Renames the account's passkey. False when the account has no passkey with this id.</summary>
    Task<bool> RenameAsync(Guid accountId, Guid passkeyId, string name, CancellationToken cancellationToken = default);

    /// <summary>Deletes the account's passkey. False when the account has no passkey with this id.</summary>
    Task<bool> DeleteAsync(Guid accountId, Guid passkeyId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Records a verified use: the new signature counter, backup state and last-used time, iff the stored counter is
    /// still <paramref name="expectedSignCount"/> (compare-and-set). False means another use of the same credential
    /// won meanwhile — two assertions verified against one counter value; the caller refuses this one.
    /// </summary>
    Task<bool> TryRecordUseAsync(Guid passkeyId, long expectedSignCount, long newSignCount, bool backedUp, DateTime nowUtc, CancellationToken cancellationToken = default);
}
