using BitosX.Api.Hosting;
using BitosX.Application.Abstractions.Persistence;
using Microsoft.Extensions.Configuration;

namespace BitosX.Api.Tests;

/// <summary>
/// The <c>migrate</c> command applies migrations with ConnectionStrings:BitosxMigrator and exits; it never
/// builds the web host, and it reports failure as a non-zero exit code instead of throwing.
/// </summary>
public sealed class MigrateCommandTests
{
    private static IConfiguration Cfg(Dictionary<string, string?> values) => new ConfigurationBuilder().AddInMemoryCollection(values).Build();

    [Theory]
    [InlineData(new[] { "migrate" }, true)]
    [InlineData(new[] { "migrate", "--environment", "Production" }, true)]
    [InlineData(new string[0], false)]
    [InlineData(new[] { "--urls", "http://127.0.0.1:5080" }, false)]
    [InlineData(new[] { "Migrate" }, false)]
    public void IsRequested_OnlyForTheExactFirstArgument(string[] args, bool expected)
        => Assert.Equal(expected, MigrateCommand.IsRequested(args));

    [Fact]
    public async Task MissingMigratorConnectionString_ExitsWith2_AndNeverReadsTheRuntimeString()
    {
        var output = new StringWriter();
        var error = new StringWriter();

        var exit = await MigrateCommand.RunAsync(Cfg(new() { ["ConnectionStrings:Bitosx"] = "Server=127.0.0.1;User ID=x;Password=runtime-secret" }), output, error);

        Assert.Equal(MigrateCommand.NotConfigured, exit);
        Assert.Contains("ConnectionStrings:BitosxMigrator", error.ToString());
        Assert.DoesNotContain("runtime-secret", error.ToString() + output.ToString());
    }

    [Fact]
    public async Task AgainstTheTestDatabase_AppliesPendingMigrations_AndExits0_Idempotently()
    {
        var migrator = TestDatabase.ConnectionString;

        var first = await MigrateCommand.RunAsync(Cfg(new() { ["ConnectionStrings:BitosxMigrator"] = migrator }), new StringWriter(), new StringWriter());
        Assert.Equal(MigrateCommand.Success, first);

        var output = new StringWriter();
        var second = await MigrateCommand.RunAsync(Cfg(new() { ["ConnectionStrings:BitosxMigrator"] = migrator }), output, new StringWriter());
        Assert.Equal(MigrateCommand.Success, second);
        Assert.Contains("up to date", output.ToString());
        Assert.DoesNotContain("Password", output.ToString(), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task UnreachableDatabase_ExitsWith1_WithoutThePassword()
    {
        var error = new StringWriter();
        var exit = await MigrateCommand.RunAsync(
            Cfg(new() { ["ConnectionStrings:BitosxMigrator"] = "Server=127.0.0.1;Port=1;User ID=migrator;Password=do-not-print-me;Connection Timeout=2" }),
            new StringWriter(), error);

        Assert.Equal(MigrateCommand.Failed, exit);
        Assert.Contains("migrate: failed", error.ToString());
        Assert.DoesNotContain("do-not-print-me", error.ToString());
    }

    [Fact]
    public async Task AppliedMigrations_AreListedByName()
    {
        var output = new StringWriter();
        var exit = await MigrateCommand.RunAsync(new FakeMigrator(["0099_example.sql"]), output, new StringWriter());

        Assert.Equal(MigrateCommand.Success, exit);
        Assert.Contains("applied 0099_example.sql", output.ToString());
    }

    private sealed class FakeMigrator(IReadOnlyList<string> applied) : IDatabaseMigrator
    {
        public Task<IReadOnlyList<string>> ApplyMigrationsAsync(CancellationToken cancellationToken = default) => Task.FromResult(applied);
    }
}
