using BitosX.Application.Accounts;

namespace BitosX.Application.Tests;

public sealed class AccountPasswordPolicyTests
{
    [Theory]
    [InlineData(12)]
    [InlineData(13)]
    [InlineData(128)]
    public void Validate_AcceptsWithinBounds(int length)
    {
        var password = new string('a', length);
        Assert.Equal(PasswordPolicyResult.Valid, AccountPasswordPolicy.Validate(password));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(11)]
    public void Validate_RejectsTooShort(int length)
    {
        Assert.Equal(PasswordPolicyResult.TooShort, AccountPasswordPolicy.Validate(new string('a', length)));
    }

    [Fact]
    public void Validate_RejectsNull() =>
        Assert.Equal(PasswordPolicyResult.TooShort, AccountPasswordPolicy.Validate(null));

    [Fact]
    public void Validate_RejectsTooLong() =>
        Assert.Equal(PasswordPolicyResult.TooLong, AccountPasswordPolicy.Validate(new string('a', 129)));

    [Fact]
    public void Validate_DoesNotTrimOrAlter()
    {
        // A password made only of spaces at the boundary lengths is accepted as-is;
        // policy must not trim (which would change/shorten the credential).
        Assert.Equal(PasswordPolicyResult.Valid, AccountPasswordPolicy.Validate(new string(' ', 12)));
        Assert.Equal(PasswordPolicyResult.TooShort, AccountPasswordPolicy.Validate(new string(' ', 11)));
    }
}
