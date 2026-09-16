using BitosX.Application.Accounts;

namespace BitosX.Application.Abstractions.Persistence;

/// <summary>
/// Persistence gateway for accounts. Defined as an abstraction here so the
/// Application layer never depends on MariaDB-specific types.
/// </summary>
public interface IAccountRepository
{
    /// <summary>Persists a new account. Throws on normalized-email uniqueness violation.</summary>
    Task AddAsync(Account account, CancellationToken cancellationToken = default);

    Task<Account?> GetByIdAsync(Guid id, CancellationToken cancellationToken = default);

    Task<Account?> GetByNormalizedEmailAsync(string normalizedEmail, CancellationToken cancellationToken = default);
}
