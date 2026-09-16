namespace BitosX.Application.Abstractions.Persistence;

/// <summary>
/// Applies pending schema migrations to the BitosX database. Implemented in
/// Infrastructure over the selected MariaDB driver.
/// </summary>
public interface IDatabaseMigrator
{
    /// <summary>
    /// Applies all not-yet-applied migrations in order, idempotently, and
    /// returns the identifiers of the migrations applied by this call.
    /// </summary>
    Task<IReadOnlyList<string>> ApplyMigrationsAsync(CancellationToken cancellationToken = default);
}
