using BitosX.Application.Versioning;

namespace BitosX.Application.Tests;

public sealed class ProductVersionTests
{
    [Theory]
    [InlineData("0.1.0", "0.1.0")]
    [InlineData("1.2.3+abc1234", "1.2.3")]          // strip build metadata
    [InlineData("  2.0.0  ", "2.0.0")]              // trim surrounding whitespace
    [InlineData("1.0.0-beta.1+sha.deadbeef", "1.0.0-beta.1")] // keep prerelease, drop metadata
    public void Normalize_ReturnsCleanVersion(string raw, string expected)
    {
        Assert.Equal(expected, ProductVersion.Normalize(raw));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Normalize_FallsBackWhenMissing(string? raw)
    {
        Assert.Equal(ProductVersion.Unknown, ProductVersion.Normalize(raw));
    }
}
