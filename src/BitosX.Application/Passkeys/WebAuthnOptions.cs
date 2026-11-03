using System.Globalization;
using System.Net;
using System.Text;

namespace BitosX.Application.Passkeys;

/// <summary>
/// The WebAuthn relying party (<c>Security:WebAuthn</c>): the RP ID the passkeys are scoped to, its display name,
/// and the exact web origins ceremonies may come from. Nothing here is secret. The section is either absent (every
/// key blank: passkeys off) or complete and valid; anything in between fails startup (<see cref="Validate"/>).
/// The ceremony policy below is fixed in code, not configuration.
/// </summary>
public sealed class WebAuthnOptions
{
    public const string SectionName = "Security:WebAuthn";

    /// <summary>Passkeys per account; registration beyond answers 409.</summary>
    public const int MaxPasskeysPerAccount = 10;

    /// <summary>Longest passkey name, in Unicode scalar values after trimming.</summary>
    public const int NameMaxLength = 64;

    /// <summary>Most origins one relying party accepts.</summary>
    public const int MaxOrigins = 10;

    /// <summary>A ceremony (registration, second step, passwordless sign-in) is single use and dies after this.</summary>
    public static readonly TimeSpan ChallengeLifetime = TimeSpan.FromMinutes(5);

    /// <summary>Random challenge length in bytes (the library's minimum is 16).</summary>
    public const int ChallengeBytes = 32;

    /// <summary>The per-account random user handle (WebAuthn <c>user.id</c>) length in bytes.</summary>
    public const int UserHandleBytes = 32;

    /// <summary>The registrable domain the passkeys belong to, e.g. <c>vault.bitosx.se</c> (lower case, no port, never an IP address).</summary>
    public string RelyingPartyId { get; set; } = string.Empty;

    /// <summary>Shown by the authenticator when a passkey is created, e.g. <c>BitosX</c>.</summary>
    public string RelyingPartyName { get; set; } = string.Empty;

    /// <summary>The web origins (scheme://host[:port]) a ceremony may come from, e.g. <c>https://vault.bitosx.se</c>.</summary>
    public IReadOnlyList<string> Origins { get; set; } = [];

    /// <summary>True when any key of the section carries a value (then all of it must be valid).</summary>
    public bool IsConfigured
        => !string.IsNullOrWhiteSpace(RelyingPartyId)
           || !string.IsNullOrWhiteSpace(RelyingPartyName)
           || Origins.Any(o => !string.IsNullOrWhiteSpace(o));

    /// <summary>
    /// Fail-closed validation of a configured section. The RP ID must be a lower-case DNS name (never an IP address)
    /// equal to, or a dot-boundary suffix of, every origin's host, and must have at least two labels (a bare top-level
    /// domain is never registrable). The public suffix list is not consulted: the operator names their own domain.
    /// Origins are exact scheme://host[:port] values without path, query, fragment or userinfo; they must be
    /// <c>https://</c>. With <paramref name="allowLocalhost"/> (Development/Testing only) the RP ID may be
    /// <c>localhost</c>, with <c>http://localhost:&lt;port&gt;</c> origins, for the local live stack.
    /// </summary>
    public void Validate(bool allowLocalhost)
    {
        var rpId = RelyingPartyId?.Trim() ?? string.Empty;
        if (rpId.Length == 0)
        {
            throw new InvalidOperationException($"{SectionName}:RelyingPartyId is required when {SectionName} is configured.");
        }

        var isLocalhost = string.Equals(rpId, "localhost", StringComparison.Ordinal);
        if (isLocalhost && !allowLocalhost)
        {
            throw new InvalidOperationException($"{SectionName}:RelyingPartyId 'localhost' is a Development/Testing-only setting; it is refused in this environment.");
        }

        if (!isLocalhost && !IsDnsName(rpId))
        {
            throw new InvalidOperationException(
                $"{SectionName}:RelyingPartyId '{rpId}' must be a lower-case domain name with at least two labels (no scheme, port, path or IP address).");
        }

        if (rpId.EndsWith(".localhost", StringComparison.Ordinal) && !allowLocalhost)
        {
            throw new InvalidOperationException($"{SectionName}:RelyingPartyId '{rpId}' is a localhost name; it is refused in this environment.");
        }

        var name = RelyingPartyName?.Trim() ?? string.Empty;
        if (name.Length is 0 or > 64 || name.Any(char.IsControl))
        {
            throw new InvalidOperationException($"{SectionName}:RelyingPartyName must be 1-64 characters without control characters.");
        }

        var origins = Origins.Where(o => !string.IsNullOrWhiteSpace(o)).Select(o => o.Trim()).ToList();
        if (origins.Count == 0)
        {
            throw new InvalidOperationException($"{SectionName}:Origins must name at least one origin.");
        }

        if (origins.Count > MaxOrigins)
        {
            throw new InvalidOperationException($"{SectionName}:Origins may name at most {MaxOrigins} origins.");
        }

        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var origin in origins)
        {
            var canonical = ValidateOrigin(origin, rpId, allowLocalhost);
            if (!seen.Add(canonical))
            {
                throw new InvalidOperationException($"{SectionName}:Origins lists '{origin}' twice.");
            }
        }

        RelyingPartyId = rpId;
        RelyingPartyName = name;
        Origins = seen.ToList();
    }

    private static string ValidateOrigin(string origin, string rpId, bool allowLocalhost)
    {
        if (!Uri.TryCreate(origin, UriKind.Absolute, out var uri)
            || !string.IsNullOrEmpty(uri.UserInfo)
            || !string.IsNullOrEmpty(uri.Query)
            || !string.IsNullOrEmpty(uri.Fragment)
            || uri.AbsolutePath != "/"
            || origin.EndsWith('/')
            || origin.Contains('?') || origin.Contains('#'))
        {
            throw new InvalidOperationException($"{SectionName}:Origins entry '{origin}' must be an exact origin: scheme://host[:port], nothing else.");
        }

        var host = uri.Host;
        var localhostOrigin = string.Equals(host, "localhost", StringComparison.Ordinal);
        if (uri.Scheme == Uri.UriSchemeHttps)
        {
            // fine everywhere
        }
        else if (uri.Scheme == Uri.UriSchemeHttp && allowLocalhost && localhostOrigin)
        {
            // the local live stack (Development/Testing only)
        }
        else
        {
            throw new InvalidOperationException(allowLocalhost
                ? $"{SectionName}:Origins entry '{origin}' must be https:// (http:// only for http://localhost:<port>)."
                : $"{SectionName}:Origins entry '{origin}' must be https://.");
        }

        if (IPAddress.TryParse(host.Trim('[', ']'), out _))
        {
            throw new InvalidOperationException($"{SectionName}:Origins entry '{origin}' uses an IP address; WebAuthn needs a domain name.");
        }

        if (!string.Equals(host, rpId, StringComparison.Ordinal) && !host.EndsWith("." + rpId, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"{SectionName}:RelyingPartyId '{rpId}' is not the host of origin '{origin}' or a registrable suffix of it.");
        }

        // The form the library compares against (scheme://host, plus the port when it is not the default).
        return uri.IsDefaultPort
            ? string.Create(CultureInfo.InvariantCulture, $"{uri.Scheme}://{host}")
            : string.Create(CultureInfo.InvariantCulture, $"{uri.Scheme}://{host}:{uri.Port}");
    }

    /// <summary>Lower-case LDH labels of 1-63 characters, at least two of them, at most 253 characters, not an IP address.</summary>
    private static bool IsDnsName(string value)
    {
        if (value.Length > 253 || IPAddress.TryParse(value, out _))
        {
            return false;
        }

        var labels = value.Split('.');
        if (labels.Length < 2)
        {
            return false;
        }

        foreach (var label in labels)
        {
            if (label.Length is 0 or > 63 || label[0] == '-' || label[^1] == '-')
            {
                return false;
            }

            foreach (var c in label)
            {
                if (!(c is >= 'a' and <= 'z' or >= '0' and <= '9' or '-'))
                {
                    return false;
                }
            }
        }

        // An all-numeric last label is never a top-level domain (and keeps dotted numbers out).
        return !labels[^1].All(char.IsAsciiDigit);
    }

    /// <summary>
    /// A passkey name as stored: trimmed, 1..<see cref="NameMaxLength"/> Unicode scalar values, valid UTF-16, no
    /// control characters, no line/paragraph separators and no bidirectional overrides or isolates. Null when invalid.
    /// </summary>
    public static string? NormalizeName(string? name)
    {
        if (name is null)
        {
            return null;
        }

        var trimmed = name.Trim();
        if (trimmed.Length == 0 || trimmed.Length > NameMaxLength * 2)
        {
            return null;
        }

        var count = 0;
        var remaining = trimmed.AsSpan();
        while (!remaining.IsEmpty)
        {
            if (Rune.DecodeFromUtf16(remaining, out var rune, out var consumed) != System.Buffers.OperationStatus.Done)
            {
                return null; // a lone surrogate
            }

            var category = Rune.GetUnicodeCategory(rune);
            if (category is UnicodeCategory.Control or UnicodeCategory.LineSeparator or UnicodeCategory.ParagraphSeparator
                || rune.Value is >= 0x202A and <= 0x202E or >= 0x2066 and <= 0x2069 or 0x200E or 0x200F or 0x061C)
            {
                return null;
            }

            count++;
            remaining = remaining[consumed..];
        }

        return count <= NameMaxLength ? trimmed : null;
    }
}

/// <summary>Whether the server offers passkeys (the Passkeys capability). Registered with Login so the password step can advertise them.</summary>
public sealed record PasskeyAvailability(bool Enabled)
{
    public static PasskeyAvailability Off { get; } = new(false);
}
