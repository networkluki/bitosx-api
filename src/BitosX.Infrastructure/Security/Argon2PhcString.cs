using System.Text;

namespace BitosX.Infrastructure.Security;

/// <summary>Parsed components of an Argon2id PHC string.</summary>
public sealed record Argon2PhcComponents(int MemoryKiB, int Iterations, int Lanes, byte[] Salt, byte[] Hash);

/// <summary>
/// Encoder/parser for Argon2id PHC strings:
/// <c>$argon2id$v=19$m=&lt;KiB&gt;,t=&lt;t&gt;,p=&lt;p&gt;$&lt;b64 salt&gt;$&lt;b64 hash&gt;</c>.
///
/// <see cref="TryParse"/> enforces STATIC structural bounds with overflow-safe
/// parsing and never allocates large buffers or runs Argon2. Configurable
/// resource ceilings (memory/iterations) are applied separately by the hasher,
/// also before any Argon2 work.
/// </summary>
public static class Argon2PhcString
{
    private const string Prefix = "$argon2id$v=19$";
    public const int MaxEncodedLength = 512;

    // Static hard structural bounds (independent of runtime config).
    public const int MinSaltBytes = 8;
    public const int MaxSaltBytes = 64;
    public const int MinHashBytes = 16;
    public const int MaxHashBytes = 64;
    public const int AbsoluteMinMemoryKiB = 8 * 1024;      // 8 MiB
    public const int AbsoluteMaxMemoryKiB = 192 * 1024;    // 192 MiB service budget ceiling
    public const int AbsoluteMaxIterations = 64;           // structural cap; config caps tighter
    public const int RequiredLanes = 1;                    // p == 1 only

    public static string Encode(int memoryKiB, int iterations, int lanes, byte[] salt, byte[] hash)
    {
        var sb = new StringBuilder(MaxEncodedLength);
        sb.Append("$argon2id$v=19$m=").Append(memoryKiB)
          .Append(",t=").Append(iterations)
          .Append(",p=").Append(lanes)
          .Append('$').Append(ToB64NoPad(salt))
          .Append('$').Append(ToB64NoPad(hash));
        return sb.ToString();
    }

    /// <summary>
    /// Structurally parses and validates a PHC string. Returns false (never throws)
    /// for anything malformed or outside the static bounds. No large allocation
    /// and no Argon2 execution occurs here.
    /// </summary>
    public static bool TryParse(string? encoded, out Argon2PhcComponents? components)
    {
        components = null;
        if (string.IsNullOrEmpty(encoded) || encoded.Length > MaxEncodedLength)
        {
            return false;
        }

        if (!encoded.StartsWith(Prefix, StringComparison.Ordinal))
        {
            return false; // wrong algorithm or version
        }

        // Remaining layout: m=..,t=..,p=..$<salt>$<hash>
        var rest = encoded[Prefix.Length..];
        var parts = rest.Split('$');
        if (parts.Length != 3)
        {
            return false;
        }

        var paramPart = parts[0];
        var saltB64 = parts[1];
        var hashB64 = parts[2];

        if (!TryParseParams(paramPart, out var m, out var t, out var p))
        {
            return false;
        }

        if (p != RequiredLanes)
        {
            return false;
        }

        if (m < AbsoluteMinMemoryKiB || m > AbsoluteMaxMemoryKiB)
        {
            return false;
        }

        if (t < 1 || t > AbsoluteMaxIterations)
        {
            return false;
        }

        if (!TryDecodeB64NoPad(saltB64, out var salt) || salt.Length < MinSaltBytes || salt.Length > MaxSaltBytes)
        {
            return false;
        }

        if (!TryDecodeB64NoPad(hashB64, out var hash) || hash.Length < MinHashBytes || hash.Length > MaxHashBytes)
        {
            return false;
        }

        components = new Argon2PhcComponents(m, t, p, salt, hash);
        return true;
    }

    private static bool TryParseParams(string paramPart, out int m, out int t, out int p)
    {
        m = t = p = 0;
        // Expect exactly: m=<int>,t=<int>,p=<int>
        var fields = paramPart.Split(',');
        if (fields.Length != 3)
        {
            return false;
        }

        return TryParseKeyedInt(fields[0], "m=", out m)
            && TryParseKeyedInt(fields[1], "t=", out t)
            && TryParseKeyedInt(fields[2], "p=", out p);
    }

    private static bool TryParseKeyedInt(string field, string key, out int value)
    {
        value = 0;
        if (!field.StartsWith(key, StringComparison.Ordinal))
        {
            return false;
        }

        var digits = field[key.Length..];
        // Overflow-safe: int.TryParse rejects values outside Int32 and non-numeric
        // input (including leading '+'/'-'/whitespace with NumberStyles.None).
        return int.TryParse(digits, System.Globalization.NumberStyles.None,
            System.Globalization.CultureInfo.InvariantCulture, out value) && value >= 0;
    }

    private static string ToB64NoPad(byte[] data) => Convert.ToBase64String(data).TrimEnd('=');

    private static bool TryDecodeB64NoPad(string value, out byte[] data)
    {
        data = [];
        if (value.Length == 0)
        {
            return false;
        }

        var padded = (value.Length % 4) switch
        {
            2 => value + "==",
            3 => value + "=",
            0 => value,
            _ => null,
        };
        if (padded is null)
        {
            return false;
        }

        var buffer = new byte[(padded.Length / 4) * 3];
        if (!Convert.TryFromBase64String(padded, buffer, out var written))
        {
            return false;
        }

        data = buffer[..written];
        return true;
    }
}
