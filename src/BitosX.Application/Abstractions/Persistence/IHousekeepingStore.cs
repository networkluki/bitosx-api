namespace BitosX.Application.Abstractions.Persistence;

/// <summary>
/// Bounded deletes of dead authentication state. Each call deletes at most <c>batchSize</c> rows through an index
/// and returns how many it deleted; the caller repeats while a full batch came back.
/// </summary>
public interface IHousekeepingStore
{
    /// <summary>Email-verification and password-reset challenges that expired before <paramref name="cutoffUtc"/> (their outbox rows cascade).</summary>
    Task<int> DeleteExpiredEmailChallengesAsync(DateTime cutoffUtc, int batchSize, CancellationToken cancellationToken = default);

    /// <summary>Second-step challenges that expired before <paramref name="cutoffUtc"/> (consumed ones expire within minutes too).</summary>
    Task<int> DeleteExpiredMfaChallengesAsync(DateTime cutoffUtc, int batchSize, CancellationToken cancellationToken = default);

    /// <summary>
    /// WebAuthn ceremonies (passkey registration and sign-in challenges) that expired before <paramref name="cutoffUtc"/>.
    /// They carry no history worth keeping, so the caller passes "now", not the retention cutoff.
    /// </summary>
    Task<int> DeleteExpiredWebAuthnChallengesAsync(DateTime cutoffUtc, int batchSize, CancellationToken cancellationToken = default);

    /// <summary>
    /// Sessions revoked, absolute-expired, or idle-expired before <paramref name="cutoffUtc"/> (idle-expired means
    /// <c>last_seen_at &lt; <paramref name="idleCutoffUtc"/></c>); their refresh tokens cascade.
    /// </summary>
    Task<int> DeleteDeadSessionsAsync(DateTime cutoffUtc, DateTime idleCutoffUtc, int batchSize, CancellationToken cancellationToken = default);
}
