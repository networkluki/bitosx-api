using System.Text;
using BitosX.Application.Mfa;

namespace BitosX.Application.Tests;

public sealed class TotpPrimitivesTests
{
    private static readonly byte[] RfcSecret = Encoding.ASCII.GetBytes("12345678901234567890");

    // RFC 6238 Appendix B (HMAC-SHA1, 8 digits, 30-second steps).
    [Theory]
    [InlineData(59L, "94287082")]
    [InlineData(1111111109L, "07081804")]
    [InlineData(1111111111L, "14050471")]
    [InlineData(1234567890L, "89005924")]
    [InlineData(2000000000L, "69279037")]
    [InlineData(20000000000L, "65353130")]
    public void Compute_MatchesRfc6238Vectors(long unixSeconds, string expected)
        => Assert.Equal(expected, Rfc6238Totp.Compute(RfcSecret, Rfc6238Totp.Step(unixSeconds, 30), 8));

    [Fact]
    public void SixDigits_IsTheLowSixOfTheEightDigitCode()
        => Assert.Equal("287082", Rfc6238Totp.Compute(RfcSecret, Rfc6238Totp.Step(59, 30), 6));

    [Fact]
    public void TryMatch_AcceptsWithinWindow_RejectsOutside()
    {
        var now = 1111111111L; // step 37037037
        var current = Rfc6238Totp.Compute(RfcSecret, Rfc6238Totp.Step(now, 30), 6);
        var previous = Rfc6238Totp.Compute(RfcSecret, Rfc6238Totp.Step(now, 30) - 1, 6);
        var twoBack = Rfc6238Totp.Compute(RfcSecret, Rfc6238Totp.Step(now, 30) - 2, 6);

        Assert.True(Rfc6238Totp.TryMatch(RfcSecret, current, now, 6, 30, 1, null, out var step));
        Assert.Equal(Rfc6238Totp.Step(now, 30), step);
        Assert.True(Rfc6238Totp.TryMatch(RfcSecret, previous, now, 6, 30, 1, null, out var prevStep));
        Assert.Equal(Rfc6238Totp.Step(now, 30) - 1, prevStep);
        Assert.False(Rfc6238Totp.TryMatch(RfcSecret, twoBack, now, 6, 30, 1, null, out _));
        Assert.True(Rfc6238Totp.TryMatch(RfcSecret, twoBack, now, 6, 30, 2, null, out _));
    }

    [Fact]
    public void TryMatch_NeverAcceptsAStepAtOrBelowTheLastUsed()
    {
        var now = 1111111111L;
        var currentStep = Rfc6238Totp.Step(now, 30);
        var current = Rfc6238Totp.Compute(RfcSecret, currentStep, 6);
        var previous = Rfc6238Totp.Compute(RfcSecret, currentStep - 1, 6);

        Assert.False(Rfc6238Totp.TryMatch(RfcSecret, current, now, 6, 30, 1, currentStep, out _));      // replay of the same step
        Assert.False(Rfc6238Totp.TryMatch(RfcSecret, previous, now, 6, 30, 1, currentStep, out _));     // older than the last used
        var next = Rfc6238Totp.Compute(RfcSecret, currentStep + 1, 6);
        Assert.True(Rfc6238Totp.TryMatch(RfcSecret, next, now, 6, 30, 1, currentStep, out _));          // newer still fine
    }

    [Theory]
    [InlineData("")]
    [InlineData("12345")]
    [InlineData("1234567")]
    [InlineData("12345a")]
    [InlineData(" 123456")]
    public void TryMatch_RejectsNonSixDigitInput(string code)
        => Assert.False(Rfc6238Totp.TryMatch(RfcSecret, code, 1111111111L, 6, 30, 1, null, out _));

    // RFC 4648 §10 Base32 vectors (padding stripped).
    [Theory]
    [InlineData("", "")]
    [InlineData("f", "MY")]
    [InlineData("fo", "MZXQ")]
    [InlineData("foo", "MZXW6")]
    [InlineData("foob", "MZXW6YQ")]
    [InlineData("fooba", "MZXW6YTB")]
    [InlineData("foobar", "MZXW6YTBOI")]
    public void Base32_RoundTripsRfc4648Vectors(string ascii, string encoded)
    {
        var bytes = Encoding.ASCII.GetBytes(ascii);
        Assert.Equal(encoded, Base32.Encode(bytes));
        Assert.True(Base32.TryDecode(encoded, out var decoded));
        Assert.Equal(bytes, decoded);
        Assert.True(Base32.TryDecode(encoded.ToLowerInvariant() + "====", out var padded)); // lenient on case and padding
        Assert.Equal(bytes, padded);
    }

    [Fact]
    public void Base32_RejectsForeignCharacters()
    {
        Assert.False(Base32.TryDecode("MZXW6YTB0I", out _)); // zero is not in the alphabet
        Assert.False(Base32.TryDecode("MZ XW", out _));
    }

    [Fact]
    public void RecoveryCodes_FormatAndCanonicalization()
    {
        var code = RecoveryCodes.Generate();
        Assert.Matches("^[abcdefghjkmnpqrstuvwxyz23456789]{5}-[abcdefghjkmnpqrstuvwxyz23456789]{5}$", code);
        var canonical = RecoveryCodes.Canonicalize(code)!;
        Assert.Equal(10, canonical.Length);
        Assert.Equal(canonical, RecoveryCodes.Canonicalize(code.ToUpperInvariant().Replace("-", " ")));
        Assert.Null(RecoveryCodes.Canonicalize("abcde-fghj0")); // 0 is not in the alphabet
        Assert.Null(RecoveryCodes.Canonicalize("abcde-fghjk-m"));
        Assert.Null(RecoveryCodes.Canonicalize(""));
        Assert.Null(RecoveryCodes.Canonicalize("123456")); // a TOTP code is never a recovery code
    }

    [Fact]
    public void TotpOptions_Validate_RejectsOutOfRange()
    {
        Assert.Throws<InvalidOperationException>(() => new TotpOptions { Digits = 5 }.Validate());
        Assert.Throws<InvalidOperationException>(() => new TotpOptions { PeriodSeconds = 5 }.Validate());
        Assert.Throws<InvalidOperationException>(() => new TotpOptions { WindowSteps = 3 }.Validate());
        Assert.Throws<InvalidOperationException>(() => new TotpOptions { Issuer = "a:b" }.Validate());
        Assert.Throws<InvalidOperationException>(() => new TotpOptions { MaxMfaAttempts = 2 }.Validate());
        new TotpOptions().Validate();
    }

    [Fact]
    public void OtpauthUri_IsWellFormed()
    {
        var uri = TotpEnrollmentService.BuildOtpauthUri("BitosX", "user+x@example.com", "MZXW6YTBOI", 6, 30);
        Assert.Equal("otpauth://totp/BitosX:user%2Bx%40example.com?secret=MZXW6YTBOI&issuer=BitosX&algorithm=SHA1&digits=6&period=30", uri);
        Assert.True(Uri.TryCreate(uri, UriKind.Absolute, out _));
    }
}
