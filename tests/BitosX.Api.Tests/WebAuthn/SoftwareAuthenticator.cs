using System.Buffers.Binary;
using System.Buffers.Text;
using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace BitosX.DevAuthenticator;

/// <summary>
/// One discoverable credential of the <see cref="SoftwareAuthenticator"/>: an ECDSA P-256 (ES256) key pair, its random
/// credential id, the user handle and RP ID it was created for, and its signature counter.
/// </summary>
public sealed class SoftwareCredential : IDisposable
{
    public SoftwareCredential(byte[] id, ECDsa key, string rpId, byte[] userHandle, uint signCount)
    {
        Id = id;
        Key = key;
        RpId = rpId;
        UserHandle = userHandle;
        SignCount = signCount;
    }

    public byte[] Id { get; }

    public ECDsa Key { get; }

    public string RpId { get; }

    public byte[] UserHandle { get; }

    /// <summary>The counter of the last signature; the next assertion uses <c>SignCount + 1</c> unless told otherwise.</summary>
    public uint SignCount { get; set; }

    public string IdBase64Url => Base64Url.EncodeToString(Id);

    /// <summary>The COSE_Key of the public key: kty EC2 (2), alg ES256 (-7), crv P-256 (1), x, y.</summary>
    public byte[] CosePublicKey()
    {
        var p = Key.ExportParameters(includePrivateParameters: false);
        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);
        writer.WriteStartMap(5);
        writer.WriteInt32(1);
        writer.WriteInt32(2);
        writer.WriteInt32(3);
        writer.WriteInt32(-7);
        writer.WriteInt32(-1);
        writer.WriteInt32(1);
        writer.WriteInt32(-2);
        writer.WriteByteString(p.Q.X!);
        writer.WriteInt32(-3);
        writer.WriteByteString(p.Q.Y!);
        writer.WriteEndMap();
        return writer.Encode();
    }

    /// <summary>The credential as JSON (private key as PKCS#8) — for the dev CLI's state file only, never for anything real.</summary>
    public JsonObject ToStateJson() => new()
    {
        ["id"] = Base64Url.EncodeToString(Id),
        ["rpId"] = RpId,
        ["userHandle"] = Base64Url.EncodeToString(UserHandle),
        ["signCount"] = SignCount,
        ["pkcs8"] = Base64Url.EncodeToString(Key.ExportPkcs8PrivateKey()),
    };

    public static SoftwareCredential FromStateJson(JsonNode node)
    {
        var key = ECDsa.Create();
        key.ImportPkcs8PrivateKey(Base64Url.DecodeFromChars(node["pkcs8"]!.GetValue<string>()), out _);
        return new SoftwareCredential(
            Base64Url.DecodeFromChars(node["id"]!.GetValue<string>()),
            key,
            node["rpId"]!.GetValue<string>(),
            Base64Url.DecodeFromChars(node["userHandle"]!.GetValue<string>()),
            node["signCount"]!.GetValue<uint>());
    }

    public void Dispose() => Key.Dispose();
}

/// <summary>
/// Knobs for producing deliberately wrong responses (negative tests). Every value left null behaves like a correct
/// platform authenticator in a browser at <see cref="SoftwareAuthenticator.Origin"/>.
/// </summary>
public sealed record AuthenticatorOverrides
{
    /// <summary>clientDataJSON.origin.</summary>
    public string? Origin { get; init; }

    /// <summary>The RP ID whose SHA-256 goes into the authenticator data (instead of the options' RP ID).</summary>
    public string? RpIdForHash { get; init; }

    /// <summary>clientDataJSON.type (instead of webauthn.create / webauthn.get).</summary>
    public string? Type { get; init; }

    /// <summary>clientDataJSON.challenge bytes (instead of the options' challenge).</summary>
    public byte[]? Challenge { get; init; }

    /// <summary>The UV flag (default set).</summary>
    public bool UserVerified { get; init; } = true;

    /// <summary>The UP flag (default set).</summary>
    public bool UserPresent { get; init; } = true;

    /// <summary>The counter in the authenticator data (default: the credential's counter + 1).</summary>
    public uint? SignCount { get; init; }

    /// <summary>The user handle returned by an assertion (default: the credential's).</summary>
    public byte[]? UserHandle { get; init; }

    /// <summary>Leave the user handle out of the assertion (as a non-discoverable credential would).</summary>
    public bool OmitUserHandle { get; init; }

    /// <summary>The BE and BS flags (a synced passkey has both).</summary>
    public bool BackupEligible { get; init; }

    public bool BackedUp { get; init; }

    /// <summary>Use this credential id at registration instead of a fresh random one (e.g. an already registered one).</summary>
    public byte[]? CredentialId { get; init; }

    /// <summary>Sign the assertion with another credential's key (signature that does not verify).</summary>
    public SoftwareCredential? SignWith { get; init; }
}

/// <summary>
/// A software WebAuthn authenticator for tests and the local dev stack: makes discoverable ES256 credentials with
/// "none" attestation and signs assertions, producing exactly the JSON a browser's <c>PublicKeyCredential.toJSON()</c>
/// returns (base64url members). It follows the options it is given (challenge, RP ID, user) and builds
/// clientDataJSON for <see cref="Origin"/>. Not an authenticator for anything real: keys live in memory (or in the
/// dev CLI's state file).
/// </summary>
public sealed class SoftwareAuthenticator
{
    /// <summary>The AAGUID this authenticator reports (all zero, as platform authenticators with "none" attestation do).</summary>
    public static readonly Guid AaGuid = Guid.Empty;

    public SoftwareAuthenticator(string origin) => Origin = origin;

    /// <summary>The origin of the page the "browser" runs the ceremony on.</summary>
    public string Origin { get; }

    /// <summary>
    /// navigator.credentials.create(): a new ES256 credential for the options' RP ID and user, returned with the
    /// registration response JSON.
    /// </summary>
    public (JsonObject Response, SoftwareCredential Credential) Create(JsonElement options, AuthenticatorOverrides? overrides = null)
    {
        overrides ??= new AuthenticatorOverrides();
        var rpId = options.GetProperty("rp").GetProperty("id").GetString()!;
        var userHandle = Base64Url.DecodeFromChars(options.GetProperty("user").GetProperty("id").GetString()!);
        var challenge = overrides.Challenge ?? Base64Url.DecodeFromChars(options.GetProperty("challenge").GetString()!);

        var credential = new SoftwareCredential(
            overrides.CredentialId ?? RandomNumberGenerator.GetBytes(32), ECDsa.Create(ECCurve.NamedCurves.nistP256), rpId, userHandle, 0);

        var clientData = ClientDataJson(overrides.Type ?? "webauthn.create", challenge, overrides.Origin ?? Origin);
        var authData = AuthenticatorData(overrides.RpIdForHash ?? rpId, Flags(overrides) | 0x40, overrides.SignCount ?? 0, credential);

        var attestation = new CborWriter(CborConformanceMode.Ctap2Canonical);
        attestation.WriteStartMap(3);
        attestation.WriteTextString("fmt");
        attestation.WriteTextString("none");
        attestation.WriteTextString("attStmt");
        attestation.WriteStartMap(0);
        attestation.WriteEndMap();
        attestation.WriteTextString("authData");
        attestation.WriteByteString(authData);
        attestation.WriteEndMap();

        var response = new JsonObject
        {
            ["id"] = credential.IdBase64Url,
            ["rawId"] = credential.IdBase64Url,
            ["type"] = "public-key",
            ["authenticatorAttachment"] = "platform",
            ["response"] = new JsonObject
            {
                ["clientDataJSON"] = Base64Url.EncodeToString(clientData),
                ["attestationObject"] = Base64Url.EncodeToString(attestation.Encode()),
                ["transports"] = new JsonArray("internal", "hybrid"),
            },
            ["clientExtensionResults"] = new JsonObject(),
        };
        return (response, credential);
    }

    /// <summary>
    /// navigator.credentials.get() with <paramref name="credential"/>: an assertion over the options' challenge, with the
    /// counter advanced (unless overridden) and the user handle included.
    /// </summary>
    public JsonObject Get(JsonElement options, SoftwareCredential credential, AuthenticatorOverrides? overrides = null)
    {
        overrides ??= new AuthenticatorOverrides();
        var rpId = options.TryGetProperty("rpId", out var r) ? r.GetString()! : credential.RpId;
        var challenge = overrides.Challenge ?? Base64Url.DecodeFromChars(options.GetProperty("challenge").GetString()!);
        var counter = overrides.SignCount ?? credential.SignCount + 1;

        var clientData = ClientDataJson(overrides.Type ?? "webauthn.get", challenge, overrides.Origin ?? Origin);
        var authData = AuthenticatorData(overrides.RpIdForHash ?? rpId, Flags(overrides), counter, null);
        var signer = (overrides.SignWith ?? credential).Key;
        var signature = signer.SignData([.. authData, .. SHA256.HashData(clientData)], HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
        credential.SignCount = counter;

        var assertion = new JsonObject
        {
            ["clientDataJSON"] = Base64Url.EncodeToString(clientData),
            ["authenticatorData"] = Base64Url.EncodeToString(authData),
            ["signature"] = Base64Url.EncodeToString(signature),
        };
        if (!overrides.OmitUserHandle)
        {
            assertion["userHandle"] = Base64Url.EncodeToString(overrides.UserHandle ?? credential.UserHandle);
        }

        return new JsonObject
        {
            ["id"] = credential.IdBase64Url,
            ["rawId"] = credential.IdBase64Url,
            ["type"] = "public-key",
            ["authenticatorAttachment"] = "platform",
            ["response"] = assertion,
            ["clientExtensionResults"] = new JsonObject(),
        };
    }

    private static byte Flags(AuthenticatorOverrides o)
        => (byte)((o.UserPresent ? 0x01 : 0) | (o.UserVerified ? 0x04 : 0) | (o.BackupEligible ? 0x08 : 0) | (o.BackedUp ? 0x10 : 0));

    private static byte[] ClientDataJson(string type, byte[] challenge, string origin)
        => Encoding.UTF8.GetBytes(new JsonObject
        {
            ["type"] = type,
            ["challenge"] = Base64Url.EncodeToString(challenge),
            ["origin"] = origin,
            ["crossOrigin"] = false,
        }.ToJsonString());

    /// <summary>rpIdHash (32) | flags (1) | signCount (4, big-endian) | [AAGUID (16) | credIdLen (2) | credId | COSE key].</summary>
    private static byte[] AuthenticatorData(string rpId, int flags, uint signCount, SoftwareCredential? attested)
    {
        var data = new List<byte>(SHA256.HashData(Encoding.UTF8.GetBytes(rpId))) { (byte)flags };
        var counter = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(counter, signCount);
        data.AddRange(counter);
        if (attested is not null)
        {
            data.AddRange(AaGuid.ToByteArray(bigEndian: true));
            var length = new byte[2];
            BinaryPrimitives.WriteUInt16BigEndian(length, (ushort)attested.Id.Length);
            data.AddRange(length);
            data.AddRange(attested.Id);
            data.AddRange(attested.CosePublicKey());
        }

        return [.. data];
    }
}
