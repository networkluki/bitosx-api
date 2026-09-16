namespace BitosX.Infrastructure.Tests;

[Collection("Persistence")]
public sealed class Migration0002Tests
{
    private readonly DatabaseFixture _fixture;

    public Migration0002Tests(DatabaseFixture fixture) => _fixture = fixture;

    [Fact]
    public async Task Migration0002_IsRecorded()
    {
        var recorded = await _fixture.GetRecordedMigrationsAsync();
        Assert.Contains("0002_account_registration_email_verification.sql", recorded);
    }

    [Fact]
    public async Task EmailOutboxTable_Exists() =>
        Assert.True(await _fixture.TableExistsAsync("email_outbox"));

    [Fact]
    public async Task InvalidatedAtColumn_Exists() =>
        Assert.True(await ColumnExistsAsync("email_verification_challenges", "invalidated_at"));

    [Fact]
    public async Task TokenHashUniqueIndex_Exists() =>
        Assert.True(await IndexExistsAsync("email_verification_challenges", "ux_evc_token_hash", unique: true));

    [Theory]
    [InlineData("id")]
    [InlineData("challenge_id")]
    [InlineData("message_type")]
    [InlineData("recipient_email")]
    [InlineData("payload_version")]
    [InlineData("payload_nonce")]
    [InlineData("payload_ciphertext")]
    [InlineData("payload_tag")]
    [InlineData("available_at")]
    [InlineData("attempt_count")]
    [InlineData("sent_at")]
    [InlineData("failed_at")]
    [InlineData("locked_until")]
    public async Task EmailOutbox_HasExpectedColumns(string column) =>
        Assert.True(await ColumnExistsAsync("email_outbox", column), $"expected email_outbox.{column}");

    private async Task<bool> ColumnExistsAsync(string table, string column)
    {
        await using var c = await _fixture.ConnectionFactory.OpenConnectionAsync();
        await using var cmd = c.CreateCommand();
        cmd.CommandText =
            "SELECT COUNT(*) FROM information_schema.columns " +
            "WHERE table_schema=DATABASE() AND table_name=@t AND column_name=@col;";
        cmd.Parameters.AddWithValue("@t", table);
        cmd.Parameters.AddWithValue("@col", column);
        return Convert.ToInt64(await cmd.ExecuteScalarAsync()) > 0;
    }

    private async Task<bool> IndexExistsAsync(string table, string index, bool unique)
    {
        await using var c = await _fixture.ConnectionFactory.OpenConnectionAsync();
        await using var cmd = c.CreateCommand();
        cmd.CommandText =
            "SELECT COUNT(*) FROM information_schema.statistics " +
            "WHERE table_schema=DATABASE() AND table_name=@t AND index_name=@i AND non_unique=@nu;";
        cmd.Parameters.AddWithValue("@t", table);
        cmd.Parameters.AddWithValue("@i", index);
        cmd.Parameters.AddWithValue("@nu", unique ? 0 : 1);
        return Convert.ToInt64(await cmd.ExecuteScalarAsync()) > 0;
    }
}
