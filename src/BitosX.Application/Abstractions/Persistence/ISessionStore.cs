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
/// Persistence for authenticated sessions. This checkpoint exposes ONLY atomic login session-create;
/// refresh rotation/reuse, logout, listing, and auth-lookup are added in later checkpoints.
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
}
