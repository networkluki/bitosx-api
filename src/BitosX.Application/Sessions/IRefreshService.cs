namespace BitosX.Application.Sessions;

/// <summary>
/// A refresh attempt carrying ONLY the plaintext opaque refresh credential. Account/session identity
/// is resolved from the credential by the store — never supplied by the caller. The record's
/// <see cref="ToString"/> redacts the token.
/// </summary>
public sealed record RefreshCommand(string RefreshToken)
{
    public override string ToString() => "RefreshCommand { RefreshToken = <redacted> }";
}

/// <summary>
/// Coarse refresh outcome. Both the store's <c>Invalid</c> and <c>ReuseDetected</c> collapse to
/// <see cref="InvalidRefresh"/> here so the future endpoint returns a single generic 401 and never
/// reveals that reuse was detected.
/// </summary>
public enum RefreshOutcome
{
    Succeeded,
    InvalidRefresh,
}

/// <summary>
/// Refresh result. On success carries the new access JWT + successor refresh token. The record's
/// <see cref="ToString"/> redacts BOTH token strings.
/// </summary>
public sealed record RefreshResult
{
    public required RefreshOutcome Outcome { get; init; }
    public string? AccessToken { get; init; }
    public DateTime AccessTokenExpiresAt { get; init; }
    public string? RefreshToken { get; init; }
    public DateTime RefreshTokenExpiresAt { get; init; }

    public static RefreshResult InvalidRefresh { get; } = new() { Outcome = RefreshOutcome.InvalidRefresh };

    public static RefreshResult Succeeded(string accessToken, DateTime accessTokenExpiresAt, string refreshToken, DateTime refreshTokenExpiresAt)
        => new()
        {
            Outcome = RefreshOutcome.Succeeded,
            AccessToken = accessToken,
            AccessTokenExpiresAt = accessTokenExpiresAt,
            RefreshToken = refreshToken,
            RefreshTokenExpiresAt = refreshTokenExpiresAt,
        };

    public override string ToString()
        => $"RefreshResult {{ Outcome = {Outcome}, AccessToken = <redacted>, AccessTokenExpiresAt = {AccessTokenExpiresAt:O}, RefreshToken = <redacted>, RefreshTokenExpiresAt = {RefreshTokenExpiresAt:O} }}";
}

/// <summary>
/// Orchestrates refresh: strictly parse the presented token to its verifier, generate a successor,
/// rotate atomically via the store (strict reuse handled there), and — only after a committed
/// rotation — issue a new access JWT. Store <c>Invalid</c> and <c>ReuseDetected</c> both collapse to
/// <see cref="RefreshOutcome.InvalidRefresh"/>; unexpected faults propagate.
/// </summary>
public interface IRefreshService
{
    Task<RefreshResult> RefreshAsync(RefreshCommand command, CancellationToken cancellationToken = default);
}
