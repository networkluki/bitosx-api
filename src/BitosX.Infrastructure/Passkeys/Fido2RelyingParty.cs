using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using BitosX.Application.Passkeys;
using Fido2NetLib;
using Fido2NetLib.Exceptions;
using Fido2NetLib.Objects;

namespace BitosX.Infrastructure.Passkeys;

/// <summary>
/// <see cref="IWebAuthnRelyingParty"/> over the Fido2 library (fido2-net-lib 4.x): <see cref="Fido2.RequestNewCredential"/>,
/// <see cref="Fido2.MakeNewCredentialAsync"/>, <see cref="Fido2.GetAssertionOptions(GetAssertionOptionsParams)"/> and
/// <see cref="Fido2.MakeAssertionAsync"/>. No metadata service and no attestation trust store: attestation conveyance
/// is <c>none</c>, and whatever statement an authenticator still sends is checked for consistency only, never trusted.
/// The options the library verifies against are rebuilt server-side from the stored challenge and the configuration
/// (never taken from the client). Every malformed or failing client response becomes <see cref="WebAuthnVerification.Failed"/>
/// with the library's error code as the log reason; nothing from the client is echoed.
/// </summary>
public sealed class Fido2RelyingParty : IWebAuthnRelyingParty
{
    /// <summary>The algorithms offered at registration, in order of preference: ES256 (-7), EdDSA (-8), RS256 (-257).</summary>
    private static readonly IReadOnlyList<PubKeyCredParam> Algorithms = [PubKeyCredParam.ES256, PubKeyCredParam.Ed25519, PubKeyCredParam.RS256];

    /// <summary>Strict, reflection-based reading of the browser's JSON (case-sensitive names, shallow depth); the models carry their own converters.</summary>
    private static readonly JsonSerializerOptions ReadOptions = new(JsonSerializerDefaults.General) { MaxDepth = 16 };

    private readonly Fido2Configuration _configuration;
    private readonly Fido2 _fido2;

    public Fido2RelyingParty(WebAuthnOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        _configuration = new Fido2Configuration
        {
            RPID = options.RelyingPartyId,
            RPName = options.RelyingPartyName,
            Origins = new HashSet<string>(options.Origins, StringComparer.Ordinal),
            ChallengeSize = WebAuthnOptions.ChallengeBytes,
            // The browser-side timeout hint matches the server-side ceremony lifetime.
            Timeout = (uint)WebAuthnOptions.ChallengeLifetime.TotalMilliseconds,
            AllowCrossOriginRequests = false,
            BackupEligibleCredentialPolicy = Fido2Configuration.CredentialBackupPolicy.Allowed,
            BackedUpCredentialPolicy = Fido2Configuration.CredentialBackupPolicy.Allowed,
        };
        _fido2 = new Fido2(_configuration, metadataService: null);
    }

    public WebAuthnCeremonyOptions BeginRegistration(byte[] userHandle, string userName, IReadOnlyList<PasskeyDescriptor> excludeCredentials)
    {
        var options = _fido2.RequestNewCredential(new RequestNewCredentialParams
        {
            User = User(userHandle, userName),
            ExcludeCredentials = Descriptors(excludeCredentials),
            AuthenticatorSelection = Selection(),
            AttestationPreference = AttestationConveyancePreference.None,
            PubKeyCredParams = Algorithms,
        });
        return new WebAuthnCeremonyOptions(options.Challenge, options.ToJson());
    }

    public async Task<RegistrationVerification> VerifyRegistrationAsync(
        byte[] challenge, byte[] userHandle, string userName, string credentialJson, CancellationToken cancellationToken = default)
    {
        AuthenticatorAttestationRawResponse? response;
        try
        {
            // response.transports is only a hint for later allow lists: drop values this library does not know (a newer
            // browser's transport must not fail the whole registration).
            var node = JsonNode.Parse(credentialJson, documentOptions: new JsonDocumentOptions { MaxDepth = ReadOptions.MaxDepth });
            if (node?["response"]?["transports"] is JsonArray transports)
            {
                foreach (var entry in transports.ToList())
                {
                    if (entry is not JsonValue value || !value.TryGetValue<string>(out var name) || ParseTransports(name) is null)
                    {
                        transports.Remove(entry);
                    }
                }
            }

            response = node?.Deserialize<AuthenticatorAttestationRawResponse>(ReadOptions);
        }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException)
        {
            return new RegistrationVerification(WebAuthnVerification.Failed, null, "malformed");
        }

        if (response?.Response is null)
        {
            return new RegistrationVerification(WebAuthnVerification.Failed, null, "malformed");
        }

        // The options exactly as issued: same challenge, RP, user, selection (UV required) and algorithms.
        var original = CredentialCreateOptions.Create(
            _configuration, challenge, User(userHandle, userName), Selection(), AttestationConveyancePreference.None, [], null, Algorithms);
        try
        {
            var credential = await _fido2.MakeNewCredentialAsync(new MakeNewCredentialParams
            {
                AttestationResponse = response,
                OriginalOptions = original,
                // Uniqueness is the caller's (it checks the store, and the store's unique key is the authority).
                IsCredentialIdUniqueToUserCallback = static (_, _) => Task.FromResult(true),
            }, cancellationToken).ConfigureAwait(false);

            var transports = credential.Transports is { Length: > 0 } t
                ? string.Join(',', t.Select(TransportName).Where(n => n is not null).Distinct())
                : null;
            return new RegistrationVerification(WebAuthnVerification.Verified, new VerifiedRegistration(
                credential.Id, credential.PublicKey, credential.SignCount, credential.AaGuid, credential.IsBackupEligible, credential.IsBackedUp,
                string.IsNullOrEmpty(transports) ? null : transports), null);
        }
        catch (Fido2VerificationException ex)
        {
            return new RegistrationVerification(WebAuthnVerification.Failed, null, ex.Code.ToString());
        }
        catch (Exception ex) when (IsMalformedInput(ex))
        {
            return new RegistrationVerification(WebAuthnVerification.Failed, null, "malformed:" + ex.GetType().Name);
        }
    }

    public WebAuthnCeremonyOptions BeginAssertion(IReadOnlyList<PasskeyDescriptor> allowCredentials, bool requireUserVerification)
    {
        var options = _fido2.GetAssertionOptions(new GetAssertionOptionsParams
        {
            AllowedCredentials = Descriptors(allowCredentials),
            UserVerification = requireUserVerification ? UserVerificationRequirement.Required : UserVerificationRequirement.Preferred,
        });
        return new WebAuthnCeremonyOptions(options.Challenge, options.ToJson());
    }

    public PasskeyAssertionClaim? ReadAssertion(string credentialJson)
    {
        var response = ReadAssertionResponse(credentialJson);
        return response?.RawId is { Length: > 0 and <= 1023 } rawId
            ? new PasskeyAssertionClaim(rawId, response.Response?.UserHandle)
            : null;
    }

    public async Task<AssertionVerification> VerifyAssertionAsync(
        byte[] challenge,
        IReadOnlyList<PasskeyDescriptor> allowCredentials,
        bool requireUserVerification,
        string credentialJson,
        byte[] storedPublicKey,
        uint storedSignCount,
        byte[] expectedCredentialId,
        byte[] expectedUserHandle,
        CancellationToken cancellationToken = default)
    {
        var response = ReadAssertionResponse(credentialJson);
        if (response?.Response?.AuthenticatorData is null || response.RawId is null)
        {
            return Failed("malformed");
        }

        if (!CryptographicOperations.FixedTimeEquals(response.RawId, expectedCredentialId))
        {
            return Failed("credential-mismatch");
        }

        // The options exactly as issued: same challenge, RP ID, allow list and user-verification requirement.
        var original = AssertionOptions.Create(
            _configuration, challenge, Descriptors(allowCredentials),
            requireUserVerification ? UserVerificationRequirement.Required : UserVerificationRequirement.Preferred, null);
        try
        {
            var result = await _fido2.MakeAssertionAsync(new MakeAssertionParams
            {
                AssertionResponse = response,
                OriginalOptions = original,
                StoredPublicKey = storedPublicKey,
                StoredSignatureCounter = storedSignCount,
                // Called by the library only when the response carries a user handle (WebAuthn §7.2 step 6).
                IsUserHandleOwnerOfCredentialIdCallback = (p, _) => Task.FromResult(
                    CryptographicOperations.FixedTimeEquals(p.UserHandle, expectedUserHandle)
                    && CryptographicOperations.FixedTimeEquals(p.CredentialId, expectedCredentialId)),
            }, cancellationToken).ConfigureAwait(false);

            var flags = AuthenticatorData.Parse(response.Response.AuthenticatorData);
            return new AssertionVerification(WebAuthnVerification.Verified, result.SignCount, result.IsBackedUp, flags.UserVerified, null);
        }
        catch (Fido2VerificationException ex) when (ex.Code == Fido2ErrorCode.InvalidSignCount)
        {
            return new AssertionVerification(WebAuthnVerification.CounterRegression, 0, false, false, ex.Code.ToString());
        }
        catch (Fido2VerificationException ex)
        {
            return Failed(ex.Code.ToString());
        }
        catch (Exception ex) when (IsMalformedInput(ex))
        {
            return Failed("malformed:" + ex.GetType().Name);
        }
    }

    private static AuthenticatorAssertionRawResponse? ReadAssertionResponse(string credentialJson)
    {
        if (string.IsNullOrEmpty(credentialJson))
        {
            return null;
        }

        try
        {
            return JsonSerializer.Deserialize<AuthenticatorAssertionRawResponse>(credentialJson, ReadOptions);
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static AssertionVerification Failed(string reason) => new(WebAuthnVerification.Failed, 0, false, false, reason);

    /// <summary>
    /// Exceptions that attacker-controlled bytes can provoke inside parsing and verification (the library funnels most
    /// into <see cref="Fido2VerificationException"/>, but not every path). Cancellation and anything else propagate.
    /// </summary>
    private static bool IsMalformedInput(Exception ex) => ex is FormatException or ArgumentException or CryptographicException
        or InvalidOperationException or NotSupportedException or NotImplementedException or KeyNotFoundException
        or InvalidCastException or OverflowException or IndexOutOfRangeException or System.Formats.Cbor.CborContentException;

    private static Fido2User User(byte[] userHandle, string userName) => new() { Id = userHandle, Name = userName, DisplayName = userName };

    private static AuthenticatorSelection Selection() => new()
    {
        ResidentKey = ResidentKeyRequirement.Required,
        UserVerification = UserVerificationRequirement.Required,
    };

    private static List<PublicKeyCredentialDescriptor> Descriptors(IReadOnlyList<PasskeyDescriptor> descriptors)
        => descriptors.Select(d => new PublicKeyCredentialDescriptor(PublicKeyCredentialType.PublicKey, d.CredentialId, ParseTransports(d.Transports))).ToList();

    private static AuthenticatorTransport[]? ParseTransports(string? stored)
    {
        if (string.IsNullOrEmpty(stored))
        {
            return null;
        }

        var parsed = stored.Split(',', StringSplitOptions.RemoveEmptyEntries)
            .Select(name => name switch
            {
                "usb" => AuthenticatorTransport.Usb,
                "nfc" => AuthenticatorTransport.Nfc,
                "ble" => AuthenticatorTransport.Ble,
                "smart-card" => AuthenticatorTransport.SmartCard,
                "hybrid" => AuthenticatorTransport.Hybrid,
                "internal" => AuthenticatorTransport.Internal,
                _ => (AuthenticatorTransport?)null,
            })
            .Where(t => t is not null)
            .Select(t => t!.Value)
            .ToArray();
        return parsed.Length == 0 ? null : parsed;
    }

    private static string? TransportName(AuthenticatorTransport transport) => transport switch
    {
        AuthenticatorTransport.Usb => "usb",
        AuthenticatorTransport.Nfc => "nfc",
        AuthenticatorTransport.Ble => "ble",
        AuthenticatorTransport.SmartCard => "smart-card",
        AuthenticatorTransport.Hybrid => "hybrid",
        AuthenticatorTransport.Internal => "internal",
        _ => null,
    };
}
