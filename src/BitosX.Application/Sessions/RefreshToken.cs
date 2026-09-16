namespace BitosX.Application.Sessions;

/// <summary>
/// A refresh token record supporting the FUTURE rotation/reuse-detection model.
///
/// The refresh token itself is a 256-bit opaque random value that is NEVER
/// stored: only its cryptographic hash (<see cref="TokenHash"/>) is persisted.
/// Rotation is represented by <see cref="ConsumedAt"/> plus
/// <see cref="ReplacedByTokenId"/>; presenting a consumed token enables reuse
/// detection. All timestamps are UTC.
/// </summary>
public sealed record RefreshToken
{
    public Guid Id { get; init; }

    public Guid SessionId { get; init; }

    /// <summary>Hash of the opaque refresh token — never the plaintext token.</summary>
    public required byte[] TokenHash { get; init; }

    public DateTime CreatedAt { get; init; }

    public DateTime ExpiresAt { get; init; }

    /// <summary>Set when the token is used (rotated) — supports reuse detection.</summary>
    public DateTime? ConsumedAt { get; init; }

    public DateTime? RevokedAt { get; init; }

    /// <summary>The token that replaced this one on rotation (rotation chain).</summary>
    public Guid? ReplacedByTokenId { get; init; }
}
