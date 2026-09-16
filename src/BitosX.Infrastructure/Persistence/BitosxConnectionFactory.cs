using MySqlConnector;

namespace BitosX.Infrastructure.Persistence;

/// <summary>
/// Creates open MariaDB connections for the BitosX database. The connection
/// string (including credentials) is supplied at composition time from a local
/// secret store — it is never embedded in source or configuration files.
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

        _connectionString = connectionString;
    }

    public async Task<MySqlConnection> OpenConnectionAsync(CancellationToken cancellationToken = default)
    {
        var connection = new MySqlConnection(_connectionString);
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        return connection;
    }
}
