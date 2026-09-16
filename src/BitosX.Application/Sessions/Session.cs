namespace BitosX.Application.Sessions;

/// <summary>
/// An authenticated session, stored separately from the account. Supports the
/// FUTURE token model (15-min access JWTs are stateless and not stored here;
/// this row anchors refresh-token lifetime and revocation).
///
/// Policy the model must support: idle lifetime 30 days (tracked via
/// <see cref="LastSeenAt"/>), absolute lifetime 90 days
/// (<see cref="AbsoluteExpiresAt"/>). All timestamps are UTC.
/// </summary>
public sealed record Session
{
    public Guid Id { get; init; }

    public Guid AccountId { get; init; }

    public DateTime CreatedAt { get; init; }

    public DateTime LastSeenAt { get; init; }

    public DateTime AbsoluteExpiresAt { get; init; }

    public DateTime? RevokedAt { get; init; }

    /// <summary>Optional non-sensitive client descriptor for auditing.</summary>
    public string? UserAgent { get; init; }
}
