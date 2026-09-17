using BitosX.Application.Security;
using Microsoft.IdentityModel.Tokens;

namespace BitosX.Infrastructure.Security;

/// <summary>
/// Validates and materializes JWT signing keys from <see cref="JwtOptions"/>, failing closed
/// on invalid key material. Shared by the issuance service and the validation-parameters
/// factory so both enforce identical key rules. Key ids are non-secret labels compared
/// exactly (ordinal). This type is Infrastructure-only (it depends on IdentityModel).
/// </summary>
internal sealed class JwtKeyMaterial
{
    public SymmetricSecurityKey CurrentKey { get; }
    public string CurrentKid { get; }
    public SymmetricSecurityKey? PreviousKey { get; }
    public string? PreviousKid { get; }

    private JwtKeyMaterial(SymmetricSecurityKey currentKey, string currentKid, SymmetricSecurityKey? previousKey, string? previousKid)
    {
        CurrentKey = currentKey;
        CurrentKid = currentKid;
        PreviousKey = previousKey;
        PreviousKid = previousKid;
    }

    public static JwtKeyMaterial FromOptions(JwtOptions options)
    {
        var currentBytes = DecodeKey(options.SigningKey, "Security:JwtSigningKey");
        if (string.IsNullOrWhiteSpace(options.KeyId))
        {
            throw new InvalidOperationException("Security:Jwt:KeyId is required (mandatory kid) when Login is enabled.");
        }

        // Previous key + previous kid must be present together, or both absent (fail closed on a partial pair).
        var previousKeySet = !string.IsNullOrWhiteSpace(options.PreviousSigningKey);
        var previousKidSet = !string.IsNullOrWhiteSpace(options.PreviousKeyId);
        if (previousKeySet != previousKidSet)
        {
            throw new InvalidOperationException(
                "Security:JwtPreviousSigningKey and Security:Jwt:PreviousKeyId must both be set, or both be absent.");
        }

        SymmetricSecurityKey? previousKey = null;
        string? previousKid = null;
        if (previousKeySet && previousKidSet)
        {
            var previousBytes = DecodeKey(options.PreviousSigningKey!, "Security:JwtPreviousSigningKey");
            previousKey = new SymmetricSecurityKey(previousBytes) { KeyId = options.PreviousKeyId };
            previousKid = options.PreviousKeyId;
        }

        var currentKey = new SymmetricSecurityKey(currentBytes) { KeyId = options.KeyId };
        return new JwtKeyMaterial(currentKey, options.KeyId, previousKey, previousKid);
    }

    // Canonical standard Base64, no whitespace, ≥ 32 decoded bytes; fails closed otherwise.
    private static byte[] DecodeKey(string base64, string name)
        => CanonicalBase64Secret.Decode(base64, name, minBytes: 32);
}
