namespace BitosX.Application.Sessions;

/// <summary>
/// A login attempt. <see cref="Password"/> is the ACCOUNT password (never the vault master
/// password / Vault Key / item password) and is used EXACTLY as supplied — no trim/case-fold/
/// Unicode normalization. <see cref="UserAgent"/> is an optional non-sensitive client descriptor.
/// </summary>
public sealed record LoginCommand(string Email, string Password, string? UserAgent = null)
{
    /// <summary>Redacts the account password AND the (account-identifying) email so a stray
    /// log/interpolation of this command leaks neither (INFO-1). UserAgent is a non-sensitive
    /// client descriptor and may remain visible.</summary>
    public override string ToString() => $"LoginCommand {{ Email = <redacted>, Password = <redacted>, UserAgent = {UserAgent} }}";
}

/// <summary>Coarse login outcome — no reason detail is exposed (anti-enumeration).</summary>
public enum LoginOutcome
{
    Succeeded,
    InvalidCredentials,

    /// <summary>Password accepted; the account has TOTP, so a second step with <see cref="LoginResult.MfaToken"/> is required.</summary>
    MfaRequired,

    /// <summary>Password accepted and TOTP is required, but the server cannot verify codes (Totp capability off). Fail closed.</summary>
    MfaUnavailable,

    /// <summary>Second sign-in step only: the account's attempt budget is used up (429, <see cref="LoginResult.RetryAfter"/>).</summary>
    RateLimited,

    /// <summary>Second sign-in step only: the per-account limiter is at capacity (generic 503, fail closed).</summary>
    TemporarilyUnavailable,
}

/// <summary>
/// Login result. On success carries the access JWT + opaque refresh token for HTTP mapping. The
/// record's <see cref="ToString"/> redacts BOTH token strings so accidental object logging never
/// leaks them.
/// </summary>
public sealed record LoginResult
{
    public required LoginOutcome Outcome { get; init; }
    public string? AccessToken { get; init; }
    public DateTime AccessTokenExpiresAt { get; init; }
    public string? RefreshToken { get; init; }
    public DateTime RefreshTokenExpiresAt { get; init; }

    /// <summary>Opaque second-step token (43-char Base64URL), set only for <see cref="LoginOutcome.MfaRequired"/>.</summary>
    public string? MfaToken { get; init; }
    public DateTime MfaTokenExpiresAt { get; init; }

    /// <summary>With <see cref="LoginOutcome.MfaRequired"/>: how the second step can be completed (<c>totp</c>, <c>recovery</c>, <c>passkey</c>).</summary>
    public IReadOnlyList<string>? MfaMethods { get; init; }

    /// <summary>With <see cref="LoginOutcome.RateLimited"/>: when the caller may try again, if known.</summary>
    public TimeSpan? RetryAfter { get; init; }

    public static LoginResult RateLimited(TimeSpan? retryAfter) => new() { Outcome = LoginOutcome.RateLimited, RetryAfter = retryAfter };

    public static LoginResult TemporarilyUnavailable { get; } = new() { Outcome = LoginOutcome.TemporarilyUnavailable };

    public static LoginResult InvalidCredentials { get; } = new() { Outcome = LoginOutcome.InvalidCredentials };

    public static LoginResult MfaUnavailable { get; } = new() { Outcome = LoginOutcome.MfaUnavailable };

    public static LoginResult MfaRequired(string mfaToken, DateTime expiresAt, IReadOnlyList<string>? methods = null)
        => new() { Outcome = LoginOutcome.MfaRequired, MfaToken = mfaToken, MfaTokenExpiresAt = expiresAt, MfaMethods = methods };

    public static LoginResult Succeeded(string accessToken, DateTime accessTokenExpiresAt, string refreshToken, DateTime refreshTokenExpiresAt)
        => new()
        {
            Outcome = LoginOutcome.Succeeded,
            AccessToken = accessToken,
            AccessTokenExpiresAt = accessTokenExpiresAt,
            RefreshToken = refreshToken,
            RefreshTokenExpiresAt = refreshTokenExpiresAt,
        };

    public override string ToString()
        => $"LoginResult {{ Outcome = {Outcome}, AccessToken = <redacted>, AccessTokenExpiresAt = {AccessTokenExpiresAt:O}, RefreshToken = <redacted>, RefreshTokenExpiresAt = {RefreshTokenExpiresAt:O}, MfaToken = <redacted> }}";
}

/// <summary>
/// Orchestrates login: bound + normalize, non-locking candidate read, Argon2 verification OUTSIDE
/// any DB lock, refresh-token generation, atomic session creation (which re-checks the exact PHC
/// under lock), then access-JWT issuance only after the session is committed. All failures collapse
/// to <see cref="LoginOutcome.InvalidCredentials"/>; unexpected faults propagate.
/// </summary>
public interface ILoginService
{
    Task<LoginResult> LoginAsync(LoginCommand command, CancellationToken cancellationToken = default);
}
