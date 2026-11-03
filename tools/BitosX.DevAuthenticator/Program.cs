using System.Text.Json;
using System.Text.Json.Nodes;
using BitosX.DevAuthenticator;

// BitosX.DevAuthenticator — development-only software passkey for the local live stack (tools/devstack/selftest.sh).
//
//   BitosX.DevAuthenticator create --origin <origin> --state <file>          < creation options JSON
//   BitosX.DevAuthenticator get    --origin <origin> --state <file> [--no-uv] < request options JSON
//
// stdin is the API's answer (an object with "options") or the options object itself. stdout is ONE line: the
// credential JSON exactly as PublicKeyCredential.toJSON() returns it in a browser at <origin>. `create` makes a new
// discoverable ES256 credential for the options' RP ID and user and appends it to the state file; `get` signs with
// the first credential the options allow (any credential for the RP ID when allowCredentials is empty) and stores
// the advanced counter. The state file holds PRIVATE KEYS in the clear (mode 0600): use it for throwaway dev
// accounts only. Exit 0 on success, 1 when no credential fits, 2 on a usage or input error.

const int Ok = 0;
const int NoCredential = 1;
const int Error = 2;

if (args.Length < 1 || args[0] is not ("create" or "get"))
{
    return Usage();
}

string? origin = null, statePath = null;
var userVerified = true;
for (var i = 1; i < args.Length; i++)
{
    switch (args[i])
    {
        case "--origin" when i + 1 < args.Length: origin = args[++i]; break;
        case "--state" when i + 1 < args.Length: statePath = args[++i]; break;
        case "--no-uv": userVerified = false; break;
        default: return Usage();
    }
}

if (origin is null || statePath is null || !Uri.TryCreate(origin, UriKind.Absolute, out _))
{
    return Usage();
}

JsonElement options;
try
{
    var input = JsonDocument.Parse(Console.In.ReadToEnd()).RootElement;
    options = (input.TryGetProperty("options", out var inner) ? inner : input).Clone();
}
catch (JsonException ex)
{
    Console.Error.WriteLine($"devauth: stdin is not JSON: {ex.Message}");
    return Error;
}

var state = File.Exists(statePath) ? JsonNode.Parse(File.ReadAllText(statePath)) as JsonArray ?? [] : [];
var credentials = state.Select(n => SoftwareCredential.FromStateJson(n!)).ToList();
var authenticator = new SoftwareAuthenticator(origin);
JsonObject output;
try
{
    if (args[0] == "create")
    {
        var (response, credential) = authenticator.Create(options, new AuthenticatorOverrides { UserVerified = userVerified });
        credentials.Add(credential);
        output = response;
    }
    else
    {
        var rpId = options.TryGetProperty("rpId", out var r) ? r.GetString() : null;
        var allowed = options.TryGetProperty("allowCredentials", out var a)
            ? a.EnumerateArray().Select(d => d.GetProperty("id").GetString()!).ToHashSet(StringComparer.Ordinal)
            : [];
        var credential = credentials.FirstOrDefault(c => (rpId is null || c.RpId == rpId) && (allowed.Count == 0 || allowed.Contains(c.IdBase64Url)));
        if (credential is null)
        {
            Console.Error.WriteLine("devauth: no stored credential fits these options");
            return NoCredential;
        }

        output = authenticator.Get(options, credential, new AuthenticatorOverrides { UserVerified = userVerified });
    }
}
catch (Exception ex) when (ex is KeyNotFoundException or InvalidOperationException or FormatException)
{
    Console.Error.WriteLine($"devauth: the options are not WebAuthn {(args[0] == "create" ? "creation" : "request")} options: {ex.Message}");
    return Error;
}

var updated = new JsonArray(credentials.Select(c => (JsonNode)c.ToStateJson()).ToArray());
File.WriteAllText(statePath, updated.ToJsonString());
if (!OperatingSystem.IsWindows())
{
    File.SetUnixFileMode(statePath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
}

Console.Out.WriteLine(output.ToJsonString());
foreach (var c in credentials)
{
    c.Dispose();
}

return Ok;

static int Usage()
{
    Console.Error.WriteLine("usage: BitosX.DevAuthenticator <create|get> --origin <origin> --state <file> [--no-uv]  (options JSON on stdin)");
    return Error;
}
