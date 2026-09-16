using System.Security.Cryptography;
using BitosX.Infrastructure.Security;

namespace BitosX.Infrastructure.Tests.Security;

public sealed class Argon2PhcStringTests
{
    [Fact]
    public void Encode_Then_Parse_RoundTrips()
    {
        var salt = RandomNumberGenerator.GetBytes(16);
        var hash = RandomNumberGenerator.GetBytes(32);
        var encoded = Argon2PhcString.Encode(47104, 3, 1, salt, hash);

        Assert.StartsWith("$argon2id$v=19$m=47104,t=3,p=1$", encoded);
        Assert.True(Argon2PhcString.TryParse(encoded, out var c));
        Assert.NotNull(c);
        Assert.Equal(47104, c!.MemoryKiB);
        Assert.Equal(3, c.Iterations);
        Assert.Equal(1, c.Lanes);
        Assert.Equal(salt, c.Salt);
        Assert.Equal(hash, c.Hash);
    }

    [Theory]
    [InlineData("")]
    [InlineData("not-a-phc")]
    [InlineData("$argon2i$v=19$m=47104,t=3,p=1$YWJjZGVmZ2g$YWJjZGVmZ2hpamtsbW5vcA")]   // argon2i
    [InlineData("$argon2id$v=16$m=47104,t=3,p=1$YWJjZGVmZ2g$YWJjZGVmZ2hpamtsbW5vcA")]  // wrong version
    [InlineData("$argon2id$v=19$m=47104,t=3$YWJjZGVmZ2g$YWJjZGVmZ2hpamtsbW5vcA")]      // missing p
    [InlineData("$argon2id$v=19$m=47104,t=3,p=2$YWJjZGVmZ2g$YWJjZGVmZ2hpamtsbW5vcA")]  // p != 1
    [InlineData("$argon2id$v=19$m=9999999999,t=3,p=1$YWJjZGVmZ2g$YWJjZGVmZ2hpamtsbW5vcA")] // overflow m
    [InlineData("$argon2id$v=19$m=100,t=3,p=1$YWJjZGVmZ2g$YWJjZGVmZ2hpamtsbW5vcA")]    // m below floor
    [InlineData("$argon2id$v=19$m=47104,t=0,p=1$YWJjZGVmZ2g$YWJjZGVmZ2hpamtsbW5vcA")]  // t=0
    [InlineData("$argon2id$v=19$m=47104,t=999,p=1$YWJjZGVmZ2g$YWJjZGVmZ2hpamtsbW5vcA")] // t above cap
    [InlineData("$argon2id$v=19$m=47104,t=3,p=1$!!!$YWJjZGVmZ2hpamtsbW5vcA")]           // bad base64 salt
    public void TryParse_RejectsMalformedOrOutOfBounds(string encoded)
    {
        Assert.False(Argon2PhcString.TryParse(encoded, out var c));
        Assert.Null(c);
    }

    [Fact]
    public void TryParse_RejectsOversizedSaltAndHash()
    {
        var bigSalt = Argon2PhcString.Encode(47104, 3, 1, RandomNumberGenerator.GetBytes(128), RandomNumberGenerator.GetBytes(32));
        Assert.False(Argon2PhcString.TryParse(bigSalt, out _));

        var bigHash = Argon2PhcString.Encode(47104, 3, 1, RandomNumberGenerator.GetBytes(16), RandomNumberGenerator.GetBytes(128));
        Assert.False(Argon2PhcString.TryParse(bigHash, out _));
    }
}
