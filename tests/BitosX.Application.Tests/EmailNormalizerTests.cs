using BitosX.Application.Accounts;

namespace BitosX.Application.Tests;

public sealed class EmailNormalizerTests
{
    [Theory]
    [InlineData("user@example.com", "USER@EXAMPLE.COM")]
    [InlineData("  User@Example.com  ", "USER@EXAMPLE.COM")]
    [InlineData("MiXeD@CaSe.IO", "MIXED@CASE.IO")]
    public void Normalize_TrimsAndUpperCases(string input, string expected)
    {
        Assert.Equal(expected, EmailNormalizer.Normalize(input));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Normalize_Throws_WhenEmailMissing(string? input)
    {
        Assert.Throws<ArgumentException>(() => EmailNormalizer.Normalize(input));
    }
}
