namespace BitosX.Application.Abstractions.Persistence;

/// <summary>
/// Outcome of an atomic login session-create. Deliberately coarse: <see cref="InvalidAccountState"/>
/// does NOT distinguish missing account / changed email / unverified / disabled / null hash / PHC
/// mismatch — the caller maps all of them to a single generic login failure (anti-enumeration).
/// </summary>
public enum LoginSessionCreateOutcome
{
    Created,
    InvalidAccountState,
}

/// <summary>
/// Inputs for creating a session + initial refresh-token row after the caller has ALREADY verified
/// the account password (Argon2) OUTSIDE any transaction/lock. Carries no plaintext password, no
/// plaintext refresh token, and no vault material — only the exact PHC string to re-check under the
/// account lock and the pre-computed SHA-256 refresh verifier.
/// </summary>
public sealed record LoginSessionCreateRequest
{
    /// <summary>Account whose row is locked and re-checked.</summary>
    public required Guid AccountId { get; init; }

    /// <summary>Normalized email the caller resolved; must still match the locked row.</summary>
    public required string NormalizedEmail { get; init; }

    /// <summary>The exact Argon2 PHC string already verified; must still equal the stored hash under lock.</summary>
    public required string ExpectedPasswordHash { get; init; }

    /// <summary>SHA-256(raw 32 token bytes) — 32 bytes; stored as the initial refresh verifier. Never the plaintext token.</summary>
    public required byte[] InitialRefreshVerifier { get; init; }

    /// <summary>Optional non-sensitive client descriptor; persisted as-is (≤ 255 chars) or NULL.</summary>
    public string? UserAgent { get; init; }
}

/// <summary>
/// Result of a login session-create. Exposes only non-secret session/refresh metadata — never the
/// refresh <c>token_hash</c>.
/// </summary>
public sealed record LoginSessionCreateResult
{
    public required LoginSessionCreateOutcome Outcome { get; init; }
    public Guid AccountId { get; init; }
    public Guid SessionId { get; init; }
    public DateTime SessionCreatedAt { get; init; }
    public DateTime SessionAbsoluteExpiresAt { get; init; }
    public DateTime RefreshTokenExpiresAt { get; init; }

    /// <summary>Shared generic failure result (no state details).</summary>
    public static LoginSessionCreateResult InvalidAccountState { get; } =
        new() { Outcome = LoginSessionCreateOutcome.InvalidAccountState };
}

/// <summary>
/// Outcome of a refresh rotation. Coarse by design: the caller maps <see cref="Invalid"/> and
/// <see cref="ReuseDetected"/> to a single generic refresh failure. <see cref="ReuseDetected"/> is a
/// security event (a consumed/revoked token was presented) — strict, with NO grace window.
/// </summary>
public enum RefreshRotationOutcome
{
    Rotated,
    Invalid,
    ReuseDetected,
}

/// <summary>
/// Inputs for a refresh rotation. Both verifiers are already <c>SHA-256(raw 32 token bytes)</c>
/// (32 bytes each) — the store never receives a plaintext refresh token, JWT, password, or vault
/// material.
/// </summary>
public sealed record RefreshRotationRequest
{
    /// <summary>Verifier of the presented (R0) token; located, locked, and re-checked.</summary>
    public required byte[] PresentedVerifier { get; init; }

    /// <summary>Verifier to persist for the new (R1) token on successful rotation.</summary>
    public required byte[] NextVerifier { get; init; }
}

/// <summary>
/// Result of a refresh rotation. Exposes only non-secret metadata on success — never a verifier,
/// <c>token_hash</c>, plaintext token, or DB row internals.
/// </summary>
public sealed record RefreshRotationResult
{
    public required RefreshRotationOutcome Outcome { get; init; }
    public Guid AccountId { get; init; }
    public Guid SessionId { get; init; }
    public DateTime RotatedAt { get; init; }
    public DateTime NextRefreshExpiresAt { get; init; }

    public static RefreshRotationResult Invalid { get; } = new() { Outcome = RefreshRotationOutcome.Invalid };
    public static RefreshRotationResult ReuseDetected { get; } = new() { Outcome = RefreshRotationOutcome.ReuseDetected };
}

/// <summary>
/// Persistence for authenticated sessions. This checkpoint exposes atomic login session-create and
/// strict refresh rotation/reuse; logout, listing, and auth-lookup are added in later checkpoints.
/// </summary>
public interface ISessionStore
{
    /// <summary>
    /// Atomically (one transaction): lock the account row, read authoritative time after the lock,
    /// re-check account state + exact PHC, then insert the session and its initial refresh-token
    /// verifier row. Returns <see cref="LoginSessionCreateOutcome.InvalidAccountState"/> (no rows
    /// written) if the locked re-check fails. Never runs Argon2.
    /// </summary>
    Task<LoginSessionCreateResult> CreateOnLoginAsync(
        LoginSessionCreateRequest request,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Atomically rotate a refresh token. A non-locking locator resolves account/session/token from
    /// the presented verifier, then locks accounts → sessions → refresh_tokens (separate statements),
    /// reads authoritative time after the locks, and re-validates. <b>Strict reuse (no grace window):</b>
    /// if the presented token is already consumed or revoked, the session and its still-active refresh
    /// tokens are revoked (session-scoped) and <see cref="RefreshRotationOutcome.ReuseDetected"/> is
    /// returned with nothing issued. An active-but-stale token → <see cref="RefreshRotationOutcome.Invalid"/>
    /// (no revocation). A fresh active token → consume R0, insert R1 (caller's <c>NextVerifier</c>), link
    /// R0→R1, bump <c>last_seen_at</c>, commit, and return <see cref="RefreshRotationOutcome.Rotated"/>.
    /// </summary>
    Task<RefreshRotationResult> RotateAsync(
        RefreshRotationRequest request,
        CancellationToken cancellationToken = default);
}
