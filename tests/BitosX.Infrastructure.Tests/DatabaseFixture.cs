using BitosX.Application.Abstractions.Persistence;
using BitosX.Infrastructure.Persistence;
using Dapper;
using Microsoft.Extensions.Configuration;
using MySqlConnector;

namespace BitosX.Infrastructure.Tests;

/// <summary>
/// Shared MariaDB fixture for persistence integration tests. Uses an ISOLATED
/// test database (connection string "BitosxTest"), applies migrations once, and
/// resets table data between test classes. It never touches the dev database.
///
/// The connection string is read from local user-secrets / environment
/// variables and is never committed.
/// </summary>
public sealed class DatabaseFixture : IAsyncLifetime
{
    public BitosxConnectionFactory ConnectionFactory { get; private set; } = null!;

    public IAccountRepository Accounts { get; private set; } = null!;

    public IReadOnlyList<string> AppliedMigrations { get; private set; } = [];

    /// <summary>
    /// A connection factory using a DML-only account on the test DB, mirroring
    /// the production runtime account's privileges. Used to prove runtime
    /// credentials cannot perform DDL.
    /// </summary>
    public BitosxConnectionFactory RuntimeConnectionFactory { get; private set; } = null!;

    public async Task InitializeAsync()
    {
        DefaultTypeMap.MatchNamesWithUnderscores = true;

        var configuration = new ConfigurationBuilder()
            .AddUserSecrets("bitosx-infrastructure-tests")
            .AddEnvironmentVariables()
            .Build();

        var connectionString = configuration.GetConnectionString("BitosxTest");
        if (string.IsNullOrWhiteSpace(connectionString))
        {
            throw new InvalidOperationException(
                "Test DB connection string 'ConnectionStrings:BitosxTest' is not configured. " +
                "Set it via user-secrets (UserSecretsId 'bitosx-infrastructure-tests') or the " +
                "environment variable ConnectionStrings__BitosxTest.");
        }

        ConnectionFactory = new BitosxConnectionFactory(connectionString);

        var migrator = new SqlMigrationRunner(ConnectionFactory);
        AppliedMigrations = await migrator.ApplyMigrationsAsync();

        Accounts = new AccountRepository(ConnectionFactory);

        var runtimeConnectionString = configuration.GetConnectionString("BitosxTestRuntime");
        if (string.IsNullOrWhiteSpace(runtimeConnectionString))
        {
            throw new InvalidOperationException(
                "Test runtime connection string 'ConnectionStrings:BitosxTestRuntime' is not configured " +
                "(a DML-only account on bitosx_test used for the DDL-denial test).");
        }

        RuntimeConnectionFactory = new BitosxConnectionFactory(runtimeConnectionString);

        await ResetAsync();
    }

    /// <summary>Removes account rows (challenge/session children cascade) and the
    /// standalone email_outbox rows so tests start clean.</summary>
    public async Task ResetAsync()
    {
        await using var connection = await ConnectionFactory.OpenConnectionAsync();
        await using var command = connection.CreateCommand();
        // email_outbox has no FK to accounts, so clear it explicitly.
        command.CommandText = "DELETE FROM email_outbox; DELETE FROM accounts;";
        await command.ExecuteNonQueryAsync();
    }

    /// <summary>Migration ids durably recorded in schema_migrations (survives across runs).</summary>
    public async Task<IReadOnlyList<string>> GetRecordedMigrationsAsync()
    {
        await using var connection = await ConnectionFactory.OpenConnectionAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT id FROM schema_migrations ORDER BY id;";
        var ids = new List<string>();
        await using var reader = await command.ExecuteReaderAsync();
        while (await reader.ReadAsync())
        {
            ids.Add(reader.GetString(0));
        }

        return ids;
    }

    public async Task<bool> TableExistsAsync(string tableName)
    {
        await using var connection = await ConnectionFactory.OpenConnectionAsync();
        await using var command = connection.CreateCommand();
        command.CommandText =
            "SELECT COUNT(*) FROM information_schema.tables " +
            "WHERE table_schema = DATABASE() AND table_name = @name;";
        command.Parameters.AddWithValue("@name", tableName);
        var count = Convert.ToInt64(await command.ExecuteScalarAsync());
        return count > 0;
    }

    public Task DisposeAsync() => Task.CompletedTask;
}

[CollectionDefinition("Persistence")]
public sealed class PersistenceCollection : ICollectionFixture<DatabaseFixture>;
