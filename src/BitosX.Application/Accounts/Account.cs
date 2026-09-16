namespace BitosX.Application.Accounts;

/// <summary>
/// Account domain model. Deliberately contains NO vault cryptographic material
/// (see the zero-knowledge boundary): there is no master password, vault key,
/// vault secret, or vault TOTP field, and there never must be.
///
/// <see cref="PasswordHash"/> is for the FUTURE account password only (a hash,
/// never plaintext) and is separate from the vault master password.
/// All timestamps are UTC.
/// </summary>
public sealed record Account
{
    public Guid Id { get; init; }

    /// <summary>Email as supplied by the user (display form).</summary>
    public required string Email { get; init; }

    /// <summary>Normalized email used for uniqueness and lookup.</summary>
    public required string NormalizedEmail { get; init; }

    public DateTime? EmailVerifiedAt { get; init; }

    /// <summary>Verified phone in E.164 form; set only after ownership verification.</summary>
    public string? PhoneE164 { get; init; }

    public DateTime? PhoneVerifiedAt { get; init; }

    /// <summary>Hash of the future account password (never plaintext); null until set.</summary>
    public string? PasswordHash { get; init; }

    public DateTime CreatedAt { get; init; }

    public DateTime UpdatedAt { get; init; }

    public DateTime? DisabledAt { get; init; }
}
