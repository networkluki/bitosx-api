using BitosX.Application.Accounts;
using MySqlConnector;

namespace BitosX.Infrastructure.Tests;

[Collection("Persistence")]
public sealed class AccountRepositoryTests
{
    private readonly DatabaseFixture _fixture;

    public AccountRepositoryTests(DatabaseFixture fixture) => _fixture = fixture;

    // Truncate to microseconds so values round-trip exactly through DATETIME(6).
    private static DateTime NowMicro()
    {
        var now = DateTime.UtcNow;
        return new DateTime(now.Ticks - (now.Ticks % 10), DateTimeKind.Utc);
    }

    private static Account NewAccount(string normalizedEmail, string? phone = null)
    {
        var ts = NowMicro();
        return new Account
        {
            Id = Guid.NewGuid(),
            Email = normalizedEmail.ToLowerInvariant(),
            NormalizedEmail = normalizedEmail,
            EmailVerifiedAt = null,
            PhoneE164 = phone,
            PhoneVerifiedAt = phone is null ? null : ts,
            PasswordHash = null,
            CreatedAt = ts,
            UpdatedAt = ts,
            DisabledAt = null,
        };
    }

    [Fact]
    public async Task Add_And_GetById_RoundTripsAllFields()
    {
        var account = NewAccount($"USER-{Guid.NewGuid():N}@EXAMPLE.COM", phone: "+15551234567");

        await _fixture.Accounts.AddAsync(account);
        var loaded = await _fixture.Accounts.GetByIdAsync(account.Id);

        Assert.NotNull(loaded);
        Assert.Equal(account.Id, loaded!.Id);
        Assert.Equal(account.Email, loaded.Email);
        Assert.Equal(account.NormalizedEmail, loaded.NormalizedEmail);
        Assert.Equal(account.PhoneE164, loaded.PhoneE164);
        Assert.Equal(account.PhoneVerifiedAt, loaded.PhoneVerifiedAt);
        Assert.Equal(account.CreatedAt, loaded.CreatedAt);
        Assert.Equal(account.UpdatedAt, loaded.UpdatedAt);
        Assert.Null(loaded.PasswordHash);
        Assert.Null(loaded.EmailVerifiedAt);
        Assert.Null(loaded.DisabledAt);
    }

    [Fact]
    public async Task GetByNormalizedEmail_ReturnsMatchingAccount()
    {
        var normalized = $"LOOKUP-{Guid.NewGuid():N}@EXAMPLE.COM";
        var account = NewAccount(normalized);

        await _fixture.Accounts.AddAsync(account);
        var loaded = await _fixture.Accounts.GetByNormalizedEmailAsync(normalized);

        Assert.NotNull(loaded);
        Assert.Equal(account.Id, loaded!.Id);
    }

    [Fact]
    public async Task Add_AllowsNullOptionalPhone()
    {
        var account = NewAccount($"NOPHONE-{Guid.NewGuid():N}@EXAMPLE.COM", phone: null);

        await _fixture.Accounts.AddAsync(account);
        var loaded = await _fixture.Accounts.GetByIdAsync(account.Id);

        Assert.NotNull(loaded);
        Assert.Null(loaded!.PhoneE164);
        Assert.Null(loaded.PhoneVerifiedAt);
    }

    [Fact]
    public async Task Add_DuplicateNormalizedEmail_Throws()
    {
        var normalized = $"DUPE-{Guid.NewGuid():N}@EXAMPLE.COM";
        await _fixture.Accounts.AddAsync(NewAccount(normalized));

        // Same normalized email, different id -> unique constraint violation.
        var duplicate = NewAccount(normalized);
        var ex = await Assert.ThrowsAsync<MySqlException>(() => _fixture.Accounts.AddAsync(duplicate));
        Assert.Equal(MySqlErrorCode.DuplicateKeyEntry, ex.ErrorCode);
    }
}
