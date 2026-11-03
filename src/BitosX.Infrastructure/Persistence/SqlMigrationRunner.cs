using System.Reflection;
using BitosX.Application.Abstractions.Persistence;
using MySqlConnector;

namespace BitosX.Infrastructure.Persistence;

/// <summary>
/// Applies embedded <c>.sql</c> migration scripts in filename order, tracking
/// applied migrations in a <c>schema_migrations</c> table so the operation is
/// idempotent; already-applied scripts are skipped.
///
/// <para>What can and cannot be atomic: MariaDB/MySQL commit every DDL statement implicitly, so a script
/// cannot be rolled back as a unit. The runner therefore (1) holds a named advisory lock
/// (<c>GET_LOCK</c>) for the whole run, so two concurrent runners can never apply the same script twice
/// or interleave scripts, and re-reads the applied set under that lock; (2) records a script only after
/// every statement in it succeeded, so a failed script is retried on the next run and never silently
/// skipped; (3) stops at the first failure with a <see cref="MigrationFailedException"/> that names the
/// script, so the operator knows exactly which script may be partially applied and must be inspected
/// (and repaired by hand if needed) before the run is repeated.</para>
/// </summary>
public sealed class SqlMigrationRunner : IDatabaseMigrator
{
    private const string MigrationResourcePrefix = "BitosX.Infrastructure.Persistence.Migrations.";

    /// <summary>The advisory lock serializing migration runs (per server, not per database).</summary>
    public const string LockName = "bitosx_schema_migrations";

    private const int LockTimeoutSeconds = 30;

    private readonly BitosxConnectionFactory _connectionFactory;

    public SqlMigrationRunner(BitosxConnectionFactory connectionFactory)
        => _connectionFactory = connectionFactory;

    public async Task<IReadOnlyList<string>> ApplyMigrationsAsync(CancellationToken cancellationToken = default)
    {
        await using var connection = await _connectionFactory.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);

        await using (var acquire = connection.CreateCommand())
        {
            acquire.CommandText = "SELECT GET_LOCK(@name, @timeout);";
            acquire.Parameters.AddWithValue("@name", LockName);
            acquire.Parameters.AddWithValue("@timeout", LockTimeoutSeconds);
            var acquired = await acquire.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
            if (acquired is null or DBNull || Convert.ToInt64(acquired, System.Globalization.CultureInfo.InvariantCulture) != 1)
            {
                throw new MigrationFailedException(null, $"Another migration run holds the '{LockName}' lock; nothing was applied.");
            }
        }

        try
        {
            return await ApplyLockedAsync(connection, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            await using var release = connection.CreateCommand();
            release.CommandText = "SELECT RELEASE_LOCK(@name);";
            release.Parameters.AddWithValue("@name", LockName);
            await release.ExecuteScalarAsync(CancellationToken.None).ConfigureAwait(false);
        }
    }

    private async Task<IReadOnlyList<string>> ApplyLockedAsync(MySqlConnection connection, CancellationToken cancellationToken)
    {
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

            try
            {
                await ExecuteAsync(connection, sql, cancellationToken).ConfigureAwait(false);
            }
            catch (MySqlException ex)
            {
                // Not recorded: the next run retries it. DDL already executed is NOT rolled back by the server.
                throw new MigrationFailedException(id,
                    $"Migration '{id}' failed and was not recorded; statements before the failure may already be applied (DDL commits implicitly). Inspect the schema before running again.",
                    ex);
            }

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

    /// <summary>The embedded migration ids, in the order they are applied.</summary>
    public static IReadOnlyList<string> KnownMigrations() => LoadMigrations().Select(m => m.Id).ToList();

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

/// <summary>A migration run stopped. <see cref="MigrationId"/> names the script that failed (null when none ran).</summary>
public sealed class MigrationFailedException : Exception
{
    public MigrationFailedException(string? migrationId, string message, Exception? inner = null)
        : base(message, inner) => MigrationId = migrationId;

    public string? MigrationId { get; }
}
