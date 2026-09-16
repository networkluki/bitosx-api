namespace BitosX.Infrastructure.Tests;

[Collection("Persistence")]
public sealed class MigrationRunnerTests
{
    private readonly DatabaseFixture _fixture;

    public MigrationRunnerTests(DatabaseFixture fixture) => _fixture = fixture;

    [Fact]
    public async Task InitialMigration_IsRecorded()
    {
        // Durable check: the migration is recorded regardless of whether THIS
        // run applied it or a previous run did (the test DB persists).
        var recorded = await _fixture.GetRecordedMigrationsAsync();
        Assert.Contains("0001_initial_account_schema.sql", recorded);
    }

    [Theory]
    [InlineData("accounts")]
    [InlineData("email_verification_challenges")]
    [InlineData("phone_verification_challenges")]
    [InlineData("sessions")]
    [InlineData("refresh_tokens")]
    [InlineData("schema_migrations")]
    public async Task Migration_CreatesExpectedTables(string table)
    {
        Assert.True(await _fixture.TableExistsAsync(table), $"Expected table '{table}' to exist.");
    }

    [Fact]
    public async Task ApplyMigrations_IsIdempotent()
    {
        // Re-running applies nothing new (migrations already recorded).
        var migrator = new BitosX.Infrastructure.Persistence.SqlMigrationRunner(_fixture.ConnectionFactory);
        var applied = await migrator.ApplyMigrationsAsync();
        Assert.Empty(applied);
    }
}
