using BitosX.Application.Abstractions.Persistence;
using BitosX.Application.Accounts;
using BitosX.Application.Email;
using BitosX.Application.Verification;
using Dapper;
using MySqlConnector;

namespace BitosX.Infrastructure.Persistence;

/// <summary>
/// Atomically creates an unverified account (NULL password hash) + first
/// verification challenge (verifier only) + encrypted outbox message.
/// </summary>
public sealed class AccountRegistrationStore : IAccountRegistrationStore
{
    private readonly BitosxConnectionFactory _connectionFactory;

    public AccountRegistrationStore(BitosxConnectionFactory connectionFactory)
        => _connectionFactory = connectionFactory;

    public async Task<RegistrationOutcome> CreateUnverifiedAccountWithChallengeAndOutboxAsync(
        Account account, EmailVerificationChallenge challenge, EmailOutboxMessage outbox,
        CancellationToken cancellationToken = default)
    {
        await using var connection = await _connectionFactory.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using var tx = await connection.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);

        try
        {
            await connection.ExecuteAsync(new CommandDefinition(
                """
                INSERT INTO accounts
                    (id, email, normalized_email, email_verified_at, phone_e164, phone_verified_at,
                     password_hash, created_at, updated_at, disabled_at)
                VALUES
                    (@Id, @Email, @NormalizedEmail, NULL, NULL, NULL, NULL, @CreatedAt, @UpdatedAt, NULL);
                """, account, tx, cancellationToken: cancellationToken)).ConfigureAwait(false);
        }
        catch (MySqlException ex) when (ex.ErrorCode == MySqlErrorCode.DuplicateKeyEntry)
        {
            await tx.RollbackAsync(cancellationToken).ConfigureAwait(false);
            return RegistrationOutcome.EmailAlreadyExists;
        }

        await connection.ExecuteAsync(new CommandDefinition(
            ChallengeInsert.Sql, challenge, tx, cancellationToken: cancellationToken)).ConfigureAwait(false);

        await connection.ExecuteAsync(new CommandDefinition(
            OutboxInsert.Sql, OutboxInsert.Params(outbox), tx, cancellationToken: cancellationToken)).ConfigureAwait(false);

        await tx.CommitAsync(cancellationToken).ConfigureAwait(false);
        return RegistrationOutcome.Created;
    }
}

/// <summary>Shared challenge INSERT (verifier + purpose, never the token) used by every store that issues a challenge.</summary>
internal static class ChallengeInsert
{
    public const string Sql =
        """
        INSERT INTO email_verification_challenges
            (id, account_id, purpose, token_hash, created_at, expires_at, consumed_at, invalidated_at, attempt_count)
        VALUES
            (@Id, @AccountId, @Purpose, @TokenHash, @CreatedAt, @ExpiresAt, NULL, NULL, 0);
        """;
}

/// <summary>Shared outbox INSERT used by the registration, verification and password-reset stores.</summary>
internal static class OutboxInsert
{
    public const string Sql =
        """
        INSERT INTO email_outbox
            (id, challenge_id, message_type, recipient_email, payload_version,
             payload_nonce, payload_ciphertext, payload_tag, created_at, available_at, attempt_count)
        VALUES
            (@Id, @ChallengeId, @MessageType, @RecipientEmail, @PayloadVersion,
             @PayloadNonce, @PayloadCiphertext, @PayloadTag, @CreatedAt, @AvailableAt, 0);
        """;

    public static object Params(EmailOutboxMessage m) => new
    {
        m.Id,
        m.ChallengeId,
        m.MessageType,
        m.RecipientEmail,
        PayloadVersion = m.Payload.Version,
        PayloadNonce = m.Payload.Nonce,
        PayloadCiphertext = m.Payload.Ciphertext,
        PayloadTag = m.Payload.Tag,
        m.CreatedAt,
        m.AvailableAt,
    };
}
