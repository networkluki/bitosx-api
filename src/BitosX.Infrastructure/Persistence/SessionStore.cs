using BitosX.Application.Abstractions.Persistence;
using BitosX.Application.Security;
using Dapper;

namespace BitosX.Infrastructure.Persistence;

/// <summary>
/// Dapper-backed <see cref="ISessionStore"/> over MariaDB. This checkpoint implements only atomic
/// login session-create: it locks the account row, reads authoritative time AFTER the lock,
/// re-checks account state + the exact PHC string already verified by the caller, then inserts the
/// session and its initial refresh-token verifier row in one transaction. It never runs Argon2,
/// never sees a plaintext password or refresh token, and never mints a JWT.
/// </summary>
public sealed class SessionStore : ISessionStore
{
    private const int UserAgentMaxLength = 255; // matches sessions.user_agent VARCHAR(255)

    private sealed record AccountLockRow(Guid Id, string NormalizedEmail, DateTime? EmailVerifiedAt, string? PasswordHash, DateTime? DisabledAt);

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
        // Internal-contract validation (programmer errors, not credential outcomes). No values logged.
        ArgumentNullException.ThrowIfNull(request);
        if (request.AccountId == Guid.Empty) throw new ArgumentException("AccountId is required.", nameof(request));
        if (string.IsNullOrWhiteSpace(request.NormalizedEmail)) throw new ArgumentException("NormalizedEmail is required.", nameof(request));
        if (string.IsNullOrWhiteSpace(request.ExpectedPasswordHash)) throw new ArgumentException("ExpectedPasswordHash is required.", nameof(request));
        ArgumentNullException.ThrowIfNull(request.InitialRefreshVerifier);
        if (request.InitialRefreshVerifier.Length != 32) throw new ArgumentException("InitialRefreshVerifier must be exactly 32 bytes.", nameof(request));
        if (request.UserAgent is { Length: > UserAgentMaxLength }) throw new ArgumentException($"UserAgent must be at most {UserAgentMaxLength} characters.", nameof(request));

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

        // Authoritative time acquired only now that the lock is held.
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
            new { Id = Guid.NewGuid(), SessionId = sessionId, TokenHash = request.InitialRefreshVerifier, Now = now, ExpiresAt = refreshExpiresAt },
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
}
