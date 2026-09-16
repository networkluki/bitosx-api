using MySqlConnector;

namespace BitosX.Infrastructure.Tests;

/// <summary>
/// Security tests proving the runtime/migrator privilege split at the database
/// level: a runtime (DML-only) account cannot perform schema-changing DDL, while
/// the migrator-capable account can (exercised by the migration runner).
/// </summary>
[Collection("Persistence")]
public sealed class DatabasePrivilegeTests
{
    private readonly DatabaseFixture _fixture;

    public DatabasePrivilegeTests(DatabaseFixture fixture) => _fixture = fixture;

    [Fact]
    public async Task RuntimeCredentials_CannotCreateTable()
    {
        await using var connection = await _fixture.RuntimeConnectionFactory.OpenConnectionAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = "CREATE TABLE ddl_denied_probe (id INT PRIMARY KEY);";

        var ex = await Assert.ThrowsAsync<MySqlException>(() => command.ExecuteNonQueryAsync());
        Assert.Contains(ex.ErrorCode, new[]
        {
            MySqlErrorCode.TableAccessDenied,     // CREATE command denied
            MySqlErrorCode.DatabaseAccessDenied,
        });
    }

    [Fact]
    public async Task RuntimeCredentials_CannotDropTable()
    {
        await using var connection = await _fixture.RuntimeConnectionFactory.OpenConnectionAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = "DROP TABLE accounts;";

        var ex = await Assert.ThrowsAsync<MySqlException>(() => command.ExecuteNonQueryAsync());
        Assert.Contains(ex.ErrorCode, new[]
        {
            MySqlErrorCode.TableAccessDenied,
            MySqlErrorCode.DatabaseAccessDenied,
        });
    }

    [Fact]
    public async Task RuntimeCredentials_CanPerformDml()
    {
        // Sanity: the runtime account CAN read (DML), confirming the failure
        // above is specifically a DDL-privilege denial, not a connectivity issue.
        await using var connection = await _fixture.RuntimeConnectionFactory.OpenConnectionAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT COUNT(*) FROM accounts;";
        var count = Convert.ToInt64(await command.ExecuteScalarAsync());
        Assert.True(count >= 0);
    }
}
