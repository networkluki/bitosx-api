using BitosX.Application.Abstractions.Persistence;
using BitosX.Application.Accounts;
using Dapper;

namespace BitosX.Infrastructure.Persistence;

/// <summary>
/// Dapper-backed <see cref="IAccountRepository"/> over MariaDB. Column names are
/// snake_case; Dapper is configured with underscore matching in
/// <see cref="PersistenceServiceCollectionExtensions"/>.
/// </summary>
public sealed class AccountRepository : IAccountRepository
{
    private const string Columns =
        "id, email, normalized_email, email_verified_at, phone_e164, phone_verified_at, " +
        "password_hash, created_at, updated_at, disabled_at";

    private readonly BitosxConnectionFactory _connectionFactory;

    public AccountRepository(BitosxConnectionFactory connectionFactory)
        => _connectionFactory = connectionFactory;

    public async Task AddAsync(Account account, CancellationToken cancellationToken = default)
    {
        await using var connection = await _connectionFactory.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);

        const string sql =
            """
            INSERT INTO accounts
                (id, email, normalized_email, email_verified_at, phone_e164, phone_verified_at,
                 password_hash, created_at, updated_at, disabled_at)
            VALUES
                (@Id, @Email, @NormalizedEmail, @EmailVerifiedAt, @PhoneE164, @PhoneVerifiedAt,
                 @PasswordHash, @CreatedAt, @UpdatedAt, @DisabledAt);
            """;

        await connection.ExecuteAsync(new CommandDefinition(sql, account, cancellationToken: cancellationToken))
            .ConfigureAwait(false);
    }

    public async Task<Account?> GetByIdAsync(Guid id, CancellationToken cancellationToken = default)
    {
        await using var connection = await _connectionFactory.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);

        var sql = $"SELECT {Columns} FROM accounts WHERE id = @id;";
        return await connection.QuerySingleOrDefaultAsync<Account>(
            new CommandDefinition(sql, new { id }, cancellationToken: cancellationToken)).ConfigureAwait(false);
    }

    public async Task<Account?> GetByNormalizedEmailAsync(
        string normalizedEmail, CancellationToken cancellationToken = default)
    {
        await using var connection = await _connectionFactory.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);

        var sql = $"SELECT {Columns} FROM accounts WHERE normalized_email = @normalizedEmail;";
        return await connection.QuerySingleOrDefaultAsync<Account>(
            new CommandDefinition(sql, new { normalizedEmail }, cancellationToken: cancellationToken)).ConfigureAwait(false);
    }
}
