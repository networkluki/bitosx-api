using BitosX.Application.Abstractions.Persistence;
using Dapper;

namespace BitosX.Infrastructure.Persistence;

/// <summary>Dapper-backed <see cref="IWebAuthnChallengeStore"/> over MariaDB. Single use is one conditional UPDATE (affected = 1).</summary>
public sealed class WebAuthnChallengeStore : IWebAuthnChallengeStore
{
    private sealed record Row(Guid Id, string Purpose, byte[]? HandleHash, Guid? AccountId, Guid? MfaChallengeId, byte[] Challenge, DateTime CreatedAt, DateTime ExpiresAt)
    {
        public WebAuthnChallenge ToChallenge() => new(Id, ParsePurpose(Purpose), HandleHash, AccountId, MfaChallengeId, Challenge, CreatedAt, ExpiresAt);
    }

    private const string Columns = """
        id AS Id, purpose AS Purpose, handle_hash AS HandleHash, account_id AS AccountId, mfa_challenge_id AS MfaChallengeId,
        challenge AS Challenge, created_at AS CreatedAt, expires_at AS ExpiresAt
        """;

    private readonly BitosxConnectionFactory _connectionFactory;

    public WebAuthnChallengeStore(BitosxConnectionFactory connectionFactory)
        => _connectionFactory = connectionFactory ?? throw new ArgumentNullException(nameof(connectionFactory));

    public async Task CreateAsync(WebAuthnChallenge challenge, CancellationToken cancellationToken = default)
    {
        Validate(challenge);
        if (challenge.Purpose == WebAuthnChallengePurpose.Mfa || challenge.HandleVerifier is not { Length: 32 })
        {
            throw new ArgumentException("A registration or passwordless ceremony carries a 32-byte handle verifier.", nameof(challenge));
        }

        if ((challenge.Purpose == WebAuthnChallengePurpose.Register) != challenge.AccountId.HasValue || challenge.MfaChallengeId is not null)
        {
            throw new ArgumentException("A registration is bound to an account; a passwordless ceremony is not.", nameof(challenge));
        }

        await using var connection = await _connectionFactory.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await connection.ExecuteAsync(new CommandDefinition(
            """
            INSERT INTO webauthn_challenges (id, purpose, handle_hash, account_id, mfa_challenge_id, challenge, created_at, expires_at, consumed_at)
            VALUES (@Id, @Purpose, @HandleVerifier, @AccountId, NULL, @Challenge, @CreatedAt, @ExpiresAt, NULL);
            """, Parameters(challenge), cancellationToken: cancellationToken)).ConfigureAwait(false);
    }

    public async Task UpsertForMfaAsync(WebAuthnChallenge challenge, CancellationToken cancellationToken = default)
    {
        Validate(challenge);
        if (challenge.Purpose != WebAuthnChallengePurpose.Mfa || challenge.MfaChallengeId is null || challenge.AccountId is null || challenge.HandleVerifier is not null)
        {
            throw new ArgumentException("A second-step ceremony is bound to an MFA challenge and its account.", nameof(challenge));
        }

        await using var connection = await _connectionFactory.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        // One row per MFA challenge: a new request replaces the earlier ceremony with a new id and challenge, so a
        // claim of the earlier one (by id) fails from now on.
        await connection.ExecuteAsync(new CommandDefinition(
            """
            INSERT INTO webauthn_challenges (id, purpose, handle_hash, account_id, mfa_challenge_id, challenge, created_at, expires_at, consumed_at)
            VALUES (@Id, @Purpose, NULL, @AccountId, @MfaChallengeId, @Challenge, @CreatedAt, @ExpiresAt, NULL)
            ON DUPLICATE KEY UPDATE id = @Id, challenge = @Challenge, created_at = @CreatedAt, expires_at = @ExpiresAt, consumed_at = NULL;
            """, Parameters(challenge), cancellationToken: cancellationToken)).ConfigureAwait(false);
    }

    public async Task<WebAuthnChallenge?> FindActiveByHandleAsync(byte[] handleVerifier, WebAuthnChallengePurpose purpose, DateTime nowUtc, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(handleVerifier);
        await using var connection = await _connectionFactory.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        var row = await connection.QuerySingleOrDefaultAsync<Row>(new CommandDefinition(
            $"SELECT {Columns} FROM webauthn_challenges WHERE handle_hash = @handleVerifier AND purpose = @purpose AND consumed_at IS NULL AND expires_at > @nowUtc;",
            new { handleVerifier, purpose = PurposeName(purpose), nowUtc }, cancellationToken: cancellationToken)).ConfigureAwait(false);
        return row?.ToChallenge();
    }

    public async Task<WebAuthnChallenge?> FindActiveForMfaAsync(Guid mfaChallengeId, DateTime nowUtc, CancellationToken cancellationToken = default)
    {
        await using var connection = await _connectionFactory.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        var row = await connection.QuerySingleOrDefaultAsync<Row>(new CommandDefinition(
            $"SELECT {Columns} FROM webauthn_challenges WHERE mfa_challenge_id = @mfaChallengeId AND purpose = 'mfa' AND consumed_at IS NULL AND expires_at > @nowUtc;",
            new { mfaChallengeId, nowUtc }, cancellationToken: cancellationToken)).ConfigureAwait(false);
        return row?.ToChallenge();
    }

    public async Task<bool> TryClaimAsync(Guid challengeId, DateTime nowUtc, CancellationToken cancellationToken = default)
    {
        await using var connection = await _connectionFactory.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        return await connection.ExecuteAsync(new CommandDefinition(
            "UPDATE webauthn_challenges SET consumed_at = @now WHERE id = @challengeId AND consumed_at IS NULL AND expires_at > @nowUtc;",
            new { challengeId, nowUtc, now = PasskeyStore.ToMicroseconds(nowUtc) }, cancellationToken: cancellationToken)).ConfigureAwait(false) == 1;
    }

    private static void Validate(WebAuthnChallenge challenge)
    {
        ArgumentNullException.ThrowIfNull(challenge);
        if (challenge.Challenge.Length is < 16 or > 64) throw new ArgumentException("A challenge is 16..64 bytes.", nameof(challenge));
        if (challenge.ExpiresAt <= challenge.CreatedAt) throw new ArgumentException("A ceremony expires after it is created.", nameof(challenge));
    }

    private static object Parameters(WebAuthnChallenge c) => new
    {
        c.Id,
        Purpose = PurposeName(c.Purpose),
        c.HandleVerifier,
        c.AccountId,
        c.MfaChallengeId,
        c.Challenge,
        CreatedAt = PasskeyStore.ToMicroseconds(c.CreatedAt),
        ExpiresAt = PasskeyStore.ToMicroseconds(c.ExpiresAt),
    };

    private static string PurposeName(WebAuthnChallengePurpose purpose) => purpose switch
    {
        WebAuthnChallengePurpose.Register => "register",
        WebAuthnChallengePurpose.Mfa => "mfa",
        WebAuthnChallengePurpose.Passwordless => "passwordless",
        _ => throw new ArgumentOutOfRangeException(nameof(purpose)),
    };

    private static WebAuthnChallengePurpose ParsePurpose(string purpose) => purpose switch
    {
        "register" => WebAuthnChallengePurpose.Register,
        "mfa" => WebAuthnChallengePurpose.Mfa,
        "passwordless" => WebAuthnChallengePurpose.Passwordless,
        _ => throw new InvalidOperationException("Unknown WebAuthn challenge purpose in the database."),
    };
}
