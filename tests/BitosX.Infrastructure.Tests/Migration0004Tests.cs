namespace BitosX.Infrastructure.Tests;

[Collection("Persistence")]
public sealed class Migration0004Tests
{
    private readonly DatabaseFixture _fixture;

    public Migration0004Tests(DatabaseFixture fixture) => _fixture = fixture;

    [Fact]
    public async Task Migration0004_IsRecorded()
    {
        var recorded = await _fixture.GetRecordedMigrationsAsync();
        Assert.Contains("0004_password_reset.sql", recorded);
    }

    [Fact]
    public async Task PurposeColumn_Exists_DefaultsToEmailVerification()
    {
        await using var c = await _fixture.ConnectionFactory.OpenConnectionAsync();
        await using var cmd = c.CreateCommand();
        cmd.CommandText =
            "SELECT column_default FROM information_schema.columns " +
            "WHERE table_schema=DATABASE() AND table_name='email_verification_challenges' AND column_name='purpose';";
        var def = (await cmd.ExecuteScalarAsync())?.ToString()?.Trim('\'');
        Assert.Equal("email_verification", def);
    }

    [Fact]
    public async Task AccountPurposeIndex_Exists()
    {
        await using var c = await _fixture.ConnectionFactory.OpenConnectionAsync();
        await using var cmd = c.CreateCommand();
        cmd.CommandText =
            "SELECT COUNT(*) FROM information_schema.statistics " +
            "WHERE table_schema=DATABASE() AND table_name='email_verification_challenges' AND index_name='ix_evc_account_purpose';";
        Assert.True(Convert.ToInt64(await cmd.ExecuteScalarAsync()) > 0);
    }
}
