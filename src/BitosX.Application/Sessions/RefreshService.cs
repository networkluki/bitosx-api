using System.Security.Cryptography;
using BitosX.Application.Abstractions.Persistence;
using BitosX.Application.Security;

namespace BitosX.Application.Sessions;

/// <summary>
/// Refresh orchestration. Strictly parses the presented token to its SHA-256 verifier (malformed →
/// generic failure, no further work), generates a successor verifier, rotates atomically via the
/// store (strict reuse is applied there), and issues a new access JWT only AFTER a committed
/// rotation, using the store's authoritative timestamp. Store <c>Invalid</c> and <c>ReuseDetected</c>
/// both collapse to <see cref="RefreshOutcome.InvalidRefresh"/>; unexpected faults propagate. Never
/// passes a plaintext refresh token to the store; owned verifier arrays are best-effort zeroed.
/// </summary>
public sealed class RefreshService : IRefreshService
{
    private readonly IRefreshTokenFactory _refreshTokenFactory;
    private readonly ISessionStore _sessionStore;
    private readonly IAccessTokenService _accessTokenService;

    public RefreshService(
        IRefreshTokenFactory refreshTokenFactory,
        ISessionStore sessionStore,
        IAccessTokenService accessTokenService)
    {
        _refreshTokenFactory = refreshTokenFactory;
        _sessionStore = sessionStore;
        _accessTokenService = accessTokenService;
    }

    public async Task<RefreshResult> RefreshAsync(RefreshCommand command, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(command);

        // Strict parse first: malformed/non-canonical/wrong-length → generic failure, no Generate/Store/JWT.
        if (!_refreshTokenFactory.TryComputeVerifier(command.RefreshToken, out var presentedVerifier))
        {
            return RefreshResult.InvalidRefresh;
        }

        byte[]? nextVerifier = null;
        try
        {
            var next = _refreshTokenFactory.Generate();
            nextVerifier = next.Verifier;

            var rotation = await _sessionStore.RotateAsync(new RefreshRotationRequest
            {
                PresentedVerifier = presentedVerifier,
                NextVerifier = next.Verifier,
            }, cancellationToken).ConfigureAwait(false);

            // Both Invalid and ReuseDetected collapse to the same generic failure; no JWT, no successor returned.
            if (rotation.Outcome != RefreshRotationOutcome.Rotated)
            {
                return RefreshResult.InvalidRefresh;
            }

            // Only after the rotation is committed: issue the new access JWT with the store's authoritative time.
            var access = _accessTokenService.Issue(rotation.AccountId, rotation.SessionId, rotation.RotatedAt);

            return RefreshResult.Succeeded(access.Token, access.ExpiresAt, next.TokenBase64Url, rotation.NextRefreshExpiresAt);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(presentedVerifier);
            if (nextVerifier is not null)
            {
                CryptographicOperations.ZeroMemory(nextVerifier);
            }
        }
    }
}
