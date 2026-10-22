namespace BitosX.Application.Abstractions.Persistence;

/// <summary>
/// A second-step challenge issued after the password was accepted. Stores only the SHA-256 verifier of
/// the opaque token the client holds, and a fingerprint of the password hash that was verified so a
/// password change between the two steps invalidates the challenge.
/// </summary>
public sealed record MfaChallenge(
    Guid Id,
    Guid AccountId,
    byte[] TokenVerifier,
    byte[] PasswordHashFingerprint,
    string? UserAgent,
    DateTime CreatedAt,
    DateTime ExpiresAt);

public sealed record MfaChallengeView(Guid Id, Guid AccountId, byte[] PasswordHashFingerprint, string? UserAgent, DateTime ExpiresAt, int AttemptCount);

public interface IMfaChallengeStore
{
    Task CreateAsync(MfaChallenge challenge, CancellationToken cancellationToken = default);

    /// <summary>An unconsumed, unexpired challenge by token verifier, or null.</summary>
    Task<MfaChallengeView?> FindActiveAsync(byte[] tokenVerifier, DateTime nowUtc, CancellationToken cancellationToken = default);

    /// <summary>Consumes the challenge iff still active (single use, atomic). False means it was spent or expired meanwhile.</summary>
    Task<bool> TryConsumeAsync(Guid challengeId, DateTime nowUtc, CancellationToken cancellationToken = default);

    /// <summary>Counts a wrong code; at <paramref name="maxAttempts"/> the challenge is consumed (the password must be entered again).</summary>
    Task RecordFailedAttemptAsync(Guid challengeId, int maxAttempts, DateTime nowUtc, CancellationToken cancellationToken = default);
}
