using System.Reflection;
using BitosX.Application.Abstractions.Persistence;
using MySqlConnector;

namespace BitosX.Infrastructure.Persistence;

/// <summary>
/// Applies embedded <c>.sql</c> migration scripts in filename order, tracking
/// applied migrations in a <c>schema_migrations</c> table so the operation is
/// idempotent. DDL statements auto-commit in MariaDB, so each script is applied
/// once and recorded; already-applied scripts are skipped.
/// </summary>
public sealed class SqlMigrationRunner : IDatabaseMigrator
{
    private const string MigrationResourcePrefix = "BitosX.Infrastructure.Persistence.Migrations.";

    private readonly BitosxConnectionFactory _connectionFactory;

    public SqlMigrationRunner(BitosxConnectionFactory connectionFactory)
        => _connectionFactory = connectionFactory;

    public async Task<IReadOnlyList<string>> ApplyMigrationsAsync(CancellationToken cancellationToken = default)
    {
        await using var connection = await _connectionFactory.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);

        await ExecuteAsync(connection,
            """
            CREATE TABLE IF NOT EXISTS schema_migrations (
                id          VARCHAR(255) NOT NULL,
                applied_at  DATETIME(6)  NOT NULL,
                CONSTRAINT pk_schema_migrations PRIMARY KEY (id)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
            """,
            cancellationToken).ConfigureAwait(false);

        var applied = await GetAppliedMigrationsAsync(connection, cancellationToken).ConfigureAwait(false);

        var newlyApplied = new List<string>();
        foreach (var (id, sql) in LoadMigrations())
        {
            if (applied.Contains(id))
            {
                continue;
            }

            await ExecuteAsync(connection, sql, cancellationToken).ConfigureAwait(false);

            await using var record = connection.CreateCommand();
            record.CommandText = "INSERT INTO schema_migrations (id, applied_at) VALUES (@id, @appliedAt);";
            record.Parameters.AddWithValue("@id", id);
            record.Parameters.AddWithValue("@appliedAt", DateTime.UtcNow);
            await record.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);

            newlyApplied.Add(id);
        }

        return newlyApplied;
    }

    private static async Task<HashSet<string>> GetAppliedMigrationsAsync(
        MySqlConnection connection, CancellationToken cancellationToken)
    {
        var applied = new HashSet<string>(StringComparer.Ordinal);
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT id FROM schema_migrations;";
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            applied.Add(reader.GetString(0));
        }

        return applied;
    }

    private static async Task ExecuteAsync(MySqlConnection connection, string sql, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Loads embedded migration scripts ordered by their identifier (filename).</summary>
    private static IEnumerable<(string Id, string Sql)> LoadMigrations()
    {
        var assembly = typeof(SqlMigrationRunner).Assembly;

        var names = assembly.GetManifestResourceNames()
            .Where(n => n.StartsWith(MigrationResourcePrefix, StringComparison.Ordinal)
                        && n.EndsWith(".sql", StringComparison.Ordinal))
            .OrderBy(n => n, StringComparer.Ordinal);

        foreach (var name in names)
        {
            var id = name[MigrationResourcePrefix.Length..];
            using var stream = assembly.GetManifestResourceStream(name)
                ?? throw new InvalidOperationException($"Migration resource '{name}' could not be opened.");
            using var streamReader = new StreamReader(stream);
            yield return (id, streamReader.ReadToEnd());
        }
    }
}
