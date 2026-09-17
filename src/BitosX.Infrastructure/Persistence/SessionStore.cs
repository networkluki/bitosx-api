using System.Security.Cryptography;
using BitosX.Application.Abstractions.Persistence;
using BitosX.Application.Security;
using Dapper;

namespace BitosX.Infrastructure.Persistence;

/// <summary>
/// Dapper-backed <see cref="ISessionStore"/> over MariaDB.
///
/// Login-create locks the account row, reads authoritative time AFTER the lock, re-checks account
/// state + the exact PHC already verified by the caller, then inserts the session and its initial
/// refresh-token verifier row in one transaction. Refresh rotation resolves the token via a
/// non-locking locator, then locks accounts → sessions → refresh_tokens (separate statements),
/// re-validates under authoritative post-lock time, and applies STRICT reuse (no grace window):
/// any presented consumed/revoked token revokes the session (session-scoped) and returns
/// ReuseDetected. The store never runs Argon2, never sees a plaintext password or refresh token,
/// and never mints a JWT. Caller-supplied verifier arrays are defensively snapshotted before the
/// first await (M-1) and best-effort zeroed afterward.
/// </summary>
public sealed class SessionStore : ISessionStore
{
    private const int UserAgentMaxLength = 255; // matches sessions.user_agent VARCHAR(255)

    private sealed record AccountLockRow(Guid Id, string NormalizedEmail, DateTime? EmailVerifiedAt, string? PasswordHash, DateTime? DisabledAt);
    private sealed record LocatorRow(Guid RefreshTokenId, Guid SessionId, Guid AccountId);
    private sealed record AccountStateRow(Guid Id, DateTime? DisabledAt);
    private sealed record SessionStateRow(Guid Id, Guid AccountId, DateTime LastSeenAt, DateTime AbsoluteExpiresAt, DateTime? RevokedAt);
    private sealed record RefreshStateRow(Guid Id, Guid SessionId, byte[] TokenHash, DateTime ExpiresAt, DateTime? ConsumedAt, DateTime? RevokedAt, Guid? ReplacedByTokenId);

    private readonly BitosxConnectionFactory _connectionFactory;
    private readonly TimeProvider _clock;
    private readonly RefreshTokenOptions _options;

    public SessionStore(BitosxConnectionFactory connectionFactory, TimeProvider clock, RefreshTokenOptions options)
    {
        _connectionFactory = connectionFactory;
        _clock = clock;
        _options = options;
    }

    public async Task<LoginSessionCreateResult> CreateOnLoginAsync(
        LoginSessionCreateRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.AccountId == Guid.Empty) throw new ArgumentException("AccountId is required.", nameof(request));
        if (string.IsNullOrWhiteSpace(request.NormalizedEmail)) throw new ArgumentException("NormalizedEmail is required.", nameof(request));
        if (string.IsNullOrWhiteSpace(request.ExpectedPasswordHash)) throw new ArgumentException("ExpectedPasswordHash is required.", nameof(request));
        ArgumentNullException.ThrowIfNull(request.InitialRefreshVerifier);
        if (request.InitialRefreshVerifier.Length != 32) throw new ArgumentException("InitialRefreshVerifier must be exactly 32 bytes.", nameof(request));
        if (request.UserAgent is { Length: > UserAgentMaxLength }) throw new ArgumentException($"UserAgent must be at most {UserAgentMaxLength} characters.", nameof(request));

        // M-1: defensive 32-byte snapshot BEFORE any await, so a caller mutating its array mid-await
        // cannot change what is persisted. Best-effort zeroed in finally (the caller's array is untouched).
        var initialVerifier = request.InitialRefreshVerifier.ToArray();
        try
        {
            await using var connection = await _connectionFactory.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
            await using var tx = await connection.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);

            // Lock the account row WITHOUT state predicates in the WHERE — lock first, evaluate state after.
            var account = await connection.QuerySingleOrDefaultAsync<AccountLockRow>(new CommandDefinition(
                """
                SELECT id, normalized_email, email_verified_at, password_hash, disabled_at
                FROM accounts
                WHERE id = @AccountId
                FOR UPDATE;
                """, new { request.AccountId }, tx, cancellationToken: cancellationToken)).ConfigureAwait(false);

            var now = _clock.GetUtcNow().UtcDateTime;

            var loginCapable = account is not null
                && account.Id == request.AccountId
                && string.Equals(account.NormalizedEmail, request.NormalizedEmail, StringComparison.Ordinal)
                && account.EmailVerifiedAt is not null
                && account.PasswordHash is not null
                && account.DisabledAt is null
                && string.Equals(account.PasswordHash, request.ExpectedPasswordHash, StringComparison.Ordinal);

            if (!loginCapable)
            {
                await tx.RollbackAsync(cancellationToken).ConfigureAwait(false);
                return LoginSessionCreateResult.InvalidAccountState;
            }

            var sessionId = Guid.NewGuid();
            var absoluteExpiresAt = now + _options.AbsoluteLifetime;
            var idleExpiresAt = now + _options.IdleLifetime;
            var refreshExpiresAt = idleExpiresAt < absoluteExpiresAt ? idleExpiresAt : absoluteExpiresAt;

            var sessionRows = await connection.ExecuteAsync(new CommandDefinition(
                """
                INSERT INTO sessions (id, account_id, created_at, last_seen_at, absolute_expires_at, revoked_at, user_agent)
                VALUES (@Id, @AccountId, @Now, @Now, @AbsoluteExpiresAt, NULL, @UserAgent);
                """,
                new { Id = sessionId, request.AccountId, Now = now, AbsoluteExpiresAt = absoluteExpiresAt, request.UserAgent },
                tx, cancellationToken: cancellationToken)).ConfigureAwait(false);

            var refreshRows = await connection.ExecuteAsync(new CommandDefinition(
                """
                INSERT INTO refresh_tokens (id, session_id, token_hash, created_at, expires_at, consumed_at, revoked_at, replaced_by_token_id)
                VALUES (@Id, @SessionId, @TokenHash, @Now, @ExpiresAt, NULL, NULL, NULL);
                """,
                new { Id = Guid.NewGuid(), SessionId = sessionId, TokenHash = initialVerifier, Now = now, ExpiresAt = refreshExpiresAt },
                tx, cancellationToken: cancellationToken)).ConfigureAwait(false);

            if (sessionRows != 1 || refreshRows != 1)
            {
                await tx.RollbackAsync(cancellationToken).ConfigureAwait(false);
                throw new InvalidOperationException("Login session-create did not affect exactly one session and one refresh row.");
            }

            await tx.CommitAsync(cancellationToken).ConfigureAwait(false);

            return new LoginSessionCreateResult
            {
                Outcome = LoginSessionCreateOutcome.Created,
                AccountId = request.AccountId,
                SessionId = sessionId,
                SessionCreatedAt = now,
                SessionAbsoluteExpiresAt = absoluteExpiresAt,
                RefreshTokenExpiresAt = refreshExpiresAt,
            };
        }
        finally
        {
            CryptographicOperations.ZeroMemory(initialVerifier);
        }
    }

    public async Task<RefreshRotationResult> RotateAsync(
        RefreshRotationRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(request.PresentedVerifier);
        ArgumentNullException.ThrowIfNull(request.NextVerifier);
        if (request.PresentedVerifier.Length != 32) throw new ArgumentException("PresentedVerifier must be exactly 32 bytes.", nameof(request));
        if (request.NextVerifier.Length != 32) throw new ArgumentException("NextVerifier must be exactly 32 bytes.", nameof(request));

        // Defensive snapshots BEFORE any await (M-1); best-effort zeroed in finally.
        var presented = request.PresentedVerifier.ToArray();
        var next = request.NextVerifier.ToArray();
        try
        {
            await using var connection = await _connectionFactory.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);

            // Non-locking locator hint (NOT authoritative state validation).
            var locator = await connection.QuerySingleOrDefaultAsync<LocatorRow>(new CommandDefinition(
                """
                SELECT rt.id AS RefreshTokenId, rt.session_id AS SessionId, s.account_id AS AccountId
                FROM refresh_tokens rt
                JOIN sessions s ON s.id = rt.session_id
                WHERE rt.token_hash = @PresentedVerifier
                LIMIT 1;
                """, new { PresentedVerifier = presented }, cancellationToken: cancellationToken)).ConfigureAwait(false);

            if (locator is null)
            {
                return RefreshRotationResult.Invalid;
            }

            await using var tx = await connection.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);

            // Lock accounts → sessions → refresh_tokens with SEPARATE statements (fixed hierarchy).
            var account = await connection.QuerySingleOrDefaultAsync<AccountStateRow>(new CommandDefinition(
                "SELECT id, disabled_at FROM accounts WHERE id = @Id FOR UPDATE;",
                new { Id = locator.AccountId }, tx, cancellationToken: cancellationToken)).ConfigureAwait(false);

            var session = await connection.QuerySingleOrDefaultAsync<SessionStateRow>(new CommandDefinition(
                "SELECT id, account_id, last_seen_at, absolute_expires_at, revoked_at FROM sessions WHERE id = @Id FOR UPDATE;",
                new { Id = locator.SessionId }, tx, cancellationToken: cancellationToken)).ConfigureAwait(false);

            var refresh = await connection.QuerySingleOrDefaultAsync<RefreshStateRow>(new CommandDefinition(
                "SELECT id, session_id, token_hash, expires_at, consumed_at, revoked_at, replaced_by_token_id FROM refresh_tokens WHERE id = @Id FOR UPDATE;",
                new { Id = locator.RefreshTokenId }, tx, cancellationToken: cancellationToken)).ConfigureAwait(false);

            // Authoritative time only after ALL locks are held.
            var now = _clock.GetUtcNow().UtcDateTime;

            // Re-validate locator relationships + exact presented-verifier match (binary, constant-time).
            var relationshipsValid = account is not null && session is not null && refresh is not null
                && session.AccountId == account.Id
                && refresh.SessionId == session.Id
                && refresh.TokenHash is not null
                && refresh.TokenHash.Length == presented.Length
                && CryptographicOperations.FixedTimeEquals(refresh.TokenHash, presented);

            if (!relationshipsValid)
            {
                await tx.RollbackAsync(cancellationToken).ConfigureAwait(false);
                return RefreshRotationResult.Invalid;
            }

            // STRICT reuse (no grace window): a consumed OR revoked presented token → revoke session + its
            // still-active tokens (session-scoped) and issue nothing.
            if (refresh!.ConsumedAt is not null || refresh.RevokedAt is not null)
            {
                await connection.ExecuteAsync(new CommandDefinition(
                    "UPDATE sessions SET revoked_at = @Now WHERE id = @SessionId AND revoked_at IS NULL;",
                    new { Now = now, SessionId = session!.Id }, tx, cancellationToken: cancellationToken)).ConfigureAwait(false);

                await connection.ExecuteAsync(new CommandDefinition(
                    "UPDATE refresh_tokens SET revoked_at = @Now WHERE session_id = @SessionId AND consumed_at IS NULL AND revoked_at IS NULL;",
                    new { Now = now, SessionId = session.Id }, tx, cancellationToken: cancellationToken)).ConfigureAwait(false);

                await tx.CommitAsync(cancellationToken).ConfigureAwait(false);
                return RefreshRotationResult.ReuseDetected;
            }

            // Freshness of an ACTIVE token. A clean expired token is Invalid WITHOUT revoking the session.
            var fresh = account!.DisabledAt is null
                && session!.RevokedAt is null
                && session.AbsoluteExpiresAt > now
                && (now - session.LastSeenAt) < _options.IdleLifetime
                && refresh.ExpiresAt > now;

            if (!fresh)
            {
                await tx.RollbackAsync(cancellationToken).ConfigureAwait(false);
                return RefreshRotationResult.Invalid;
            }

            // Normal rotation.
            var consumeRows = await connection.ExecuteAsync(new CommandDefinition(
                "UPDATE refresh_tokens SET consumed_at = @Now WHERE id = @Id AND consumed_at IS NULL AND revoked_at IS NULL;",
                new { Now = now, refresh.Id }, tx, cancellationToken: cancellationToken)).ConfigureAwait(false);
            if (consumeRows != 1)
            {
                await tx.RollbackAsync(cancellationToken).ConfigureAwait(false);
                throw new InvalidOperationException("Refresh rotation failed to consume exactly one active token.");
            }

            var idleExpiresAt = now + _options.IdleLifetime;
            var nextExpiresAt = idleExpiresAt < session!.AbsoluteExpiresAt ? idleExpiresAt : session.AbsoluteExpiresAt;
            var nextId = Guid.NewGuid();

            var insertRows = await connection.ExecuteAsync(new CommandDefinition(
                """
                INSERT INTO refresh_tokens (id, session_id, token_hash, created_at, expires_at, consumed_at, revoked_at, replaced_by_token_id)
                VALUES (@Id, @SessionId, @TokenHash, @Now, @ExpiresAt, NULL, NULL, NULL);
                """,
                new { Id = nextId, SessionId = session.Id, TokenHash = next, Now = now, ExpiresAt = nextExpiresAt },
                tx, cancellationToken: cancellationToken)).ConfigureAwait(false);
            if (insertRows != 1)
            {
                await tx.RollbackAsync(cancellationToken).ConfigureAwait(false);
                throw new InvalidOperationException("Refresh rotation failed to insert exactly one new token.");
            }

            var linkRows = await connection.ExecuteAsync(new CommandDefinition(
                "UPDATE refresh_tokens SET replaced_by_token_id = @NextId WHERE id = @Id;",
                new { NextId = nextId, refresh.Id }, tx, cancellationToken: cancellationToken)).ConfigureAwait(false);
            if (linkRows != 1)
            {
                await tx.RollbackAsync(cancellationToken).ConfigureAwait(false);
                throw new InvalidOperationException("Refresh rotation failed to link exactly one predecessor token.");
            }

            var sessionRows = await connection.ExecuteAsync(new CommandDefinition(
                "UPDATE sessions SET last_seen_at = @Now WHERE id = @SessionId AND revoked_at IS NULL;",
                new { Now = now, SessionId = session.Id }, tx, cancellationToken: cancellationToken)).ConfigureAwait(false);
            if (sessionRows != 1)
            {
                await tx.RollbackAsync(cancellationToken).ConfigureAwait(false);
                throw new InvalidOperationException("Refresh rotation failed to update exactly one active session.");
            }

            await tx.CommitAsync(cancellationToken).ConfigureAwait(false);

            return new RefreshRotationResult
            {
                Outcome = RefreshRotationOutcome.Rotated,
                AccountId = account.Id,
                SessionId = session.Id,
                RotatedAt = now,
                NextRefreshExpiresAt = nextExpiresAt,
            };
        }
        finally
        {
            CryptographicOperations.ZeroMemory(presented);
            CryptographicOperations.ZeroMemory(next);
        }
    }
}
