using MySqlConnector;

namespace BitosX.Infrastructure.Persistence;

/// <summary>
/// Creates open MariaDB connections for the BitosX database. The connection
/// string (including credentials) is supplied at composition time from a local
/// secret store — it is never embedded in source or configuration files.
///
/// Every timestamp column is UTC <c>DATETIME(6)</c>. The factory forces MySqlConnector's
/// <c>DateTimeKind=Utc</c> option whatever the configured string says, so every <see cref="DateTime"/>
/// read from the database carries <see cref="DateTimeKind.Utc"/> and is serialized with an explicit
/// <c>Z</c>. The same option makes the driver reject a <see cref="DateTimeKind.Local"/> parameter, so a
/// local time can never be written by mistake.
/// </summary>
public sealed class BitosxConnectionFactory
{
    private readonly string _connectionString;

    public BitosxConnectionFactory(string connectionString)
    {
        if (string.IsNullOrWhiteSpace(connectionString))
        {
            throw new ArgumentException("A BitosX database connection string is required.", nameof(connectionString));
        }

        _connectionString = new MySqlConnectionStringBuilder(connectionString)
        {
            DateTimeKind = MySqlDateTimeKind.Utc,
        }.ConnectionString;
    }

    public async Task<MySqlConnection> OpenConnectionAsync(CancellationToken cancellationToken = default)
    {
        var connection = new MySqlConnection(_connectionString);
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        return connection;
    }
}
