namespace BitosX.Infrastructure.Tests;

[Collection("Persistence")]
public sealed class Migration0005Tests
{
    private readonly DatabaseFixture _fixture;

    public Migration0005Tests(DatabaseFixture fixture) => _fixture = fixture;

    [Fact]
    public async Task Migration0005_IsRecorded()
        => Assert.Contains("0005_totp_second_factor.sql", await _fixture.GetRecordedMigrationsAsync());

    [Theory]
    [InlineData("account_totp")]
    [InlineData("account_recovery_codes")]
    [InlineData("mfa_challenges")]
    public async Task Tables_Exist(string table) => Assert.True(await _fixture.TableExistsAsync(table));
}
