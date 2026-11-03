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

    /// <summary>
    /// Reserves one code attempt BEFORE the code is checked, atomically: one conditional UPDATE that succeeds only
    /// while the challenge is active and has used fewer than <paramref name="maxAttempts"/> attempts. False means
    /// no attempt is left (or the challenge is spent/expired), so the code must not be checked at all. Concurrent
    /// requests therefore get at most <paramref name="maxAttempts"/> code checks per challenge in total.
    /// </summary>
    Task<bool> TryReserveAttemptAsync(Guid challengeId, int maxAttempts, DateTime nowUtc, CancellationToken cancellationToken = default);

    /// <summary>After a wrong code: consumes the challenge once its reserved attempts reached <paramref name="maxAttempts"/> (the password must be entered again).</summary>
    Task CloseIfAttemptsExhaustedAsync(Guid challengeId, int maxAttempts, DateTime nowUtc, CancellationToken cancellationToken = default);
}
