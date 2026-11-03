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

[Collection("Persistence")]
public sealed class MigrationRunnerLockingTests
{
    private readonly DatabaseFixture _fixture;

    public MigrationRunnerLockingTests(DatabaseFixture fixture) => _fixture = fixture;

    [Fact]
    public async Task EveryEmbeddedMigration_IsRecorded_InOrder()
    {
        var known = BitosX.Infrastructure.Persistence.SqlMigrationRunner.KnownMigrations();
        var recorded = await _fixture.GetRecordedMigrationsAsync();
        Assert.Equal(known, recorded.Where(known.Contains).ToList());
        Assert.Contains("0008_payload_size_recovery_code_scope_housekeeping_indexes.sql", recorded);
    }

    [Fact]
    public async Task ConcurrentRuns_Serialize_AndApplyNothingTwice()
    {
        var runs = await Task.WhenAll(Enumerable.Range(0, 4).Select(_ =>
            new BitosX.Infrastructure.Persistence.SqlMigrationRunner(_fixture.ConnectionFactory).ApplyMigrationsAsync()));
        Assert.All(runs, Assert.Empty);
    }

    [Fact]
    public async Task WhileAnotherRunHoldsTheLock_ARunIsRefused_NotInterleaved()
    {
        await using var holder = await _fixture.ConnectionFactory.OpenConnectionAsync();
        await using (var cmd = holder.CreateCommand())
        {
            cmd.CommandText = $"SELECT GET_LOCK('{BitosX.Infrastructure.Persistence.SqlMigrationRunner.LockName}', 0);";
            Assert.Equal(1L, Convert.ToInt64(await cmd.ExecuteScalarAsync()));
        }

        try
        {
            // The runner waits up to its lock timeout; cut the wait short by cancelling after a moment.
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(2));
            var run = new BitosX.Infrastructure.Persistence.SqlMigrationRunner(_fixture.ConnectionFactory).ApplyMigrationsAsync(cts.Token);
            await Assert.ThrowsAnyAsync<Exception>(() => run);
        }
        finally
        {
            await using var release = holder.CreateCommand();
            release.CommandText = $"SELECT RELEASE_LOCK('{BitosX.Infrastructure.Persistence.SqlMigrationRunner.LockName}');";
            await release.ExecuteScalarAsync();
        }
    }
}
