namespace BitosX.Application.Mfa;

/// <summary>RFC 4648 Base32 (upper-case alphabet, no padding) as authenticator apps expect secrets.</summary>
public static class Base32
{
    private const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    public static string Encode(ReadOnlySpan<byte> data)
    {
        var output = new char[(data.Length * 8 + 4) / 5];
        var index = 0;
        var buffer = 0;
        var bits = 0;
        foreach (var b in data)
        {
            buffer = (buffer << 8) | b;
            bits += 8;
            while (bits >= 5)
            {
                bits -= 5;
                output[index++] = Alphabet[(buffer >> bits) & 0x1F];
            }
        }

        if (bits > 0)
        {
            output[index++] = Alphabet[(buffer << (5 - bits)) & 0x1F];
        }

        return new string(output, 0, index);
    }

    /// <summary>Decodes unpadded or padded Base32; case-insensitive; returns false on any other character.</summary>
    public static bool TryDecode(string text, out byte[] data)
    {
        data = [];
        if (text is null) return false;
        var trimmed = text.TrimEnd('=');
        var output = new List<byte>(trimmed.Length * 5 / 8);
        var buffer = 0;
        var bits = 0;
        foreach (var raw in trimmed)
        {
            var c = char.ToUpperInvariant(raw);
            var value = Alphabet.IndexOf(c);
            if (value < 0) return false;
            buffer = (buffer << 5) | value;
            bits += 5;
            if (bits >= 8)
            {
                bits -= 8;
                output.Add((byte)((buffer >> bits) & 0xFF));
            }
        }

        data = output.ToArray();
        return true;
    }
}
