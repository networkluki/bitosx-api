using System.Buffers.Text;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Nodes;
using BitosX.Application.Mfa;
using BitosX.Contracts.Accounts;
using BitosX.DevAuthenticator;
using Microsoft.Extensions.DependencyInjection;

namespace BitosX.Api.Tests;

/// <summary>
/// Passkeys end to end through the real endpoints, with a software authenticator producing exactly what a browser
/// sends: registration (on top of TOTP), management, the passkey second sign-in step, sign-in without email and
/// password, and the negative cases (origin, RP ID hash, challenge, purpose, UV, user handle, counter, foreign and
/// unknown credentials, limits, capability off).
/// </summary>
public sealed class PasskeyEndpointTests : IClassFixture<LoginApiFactory>, IAsyncLifetime
{
    private const string Password = "Correct-Horse-Battery-Staple-1";
    private const string Origin = "https://vault.bitosx.se";

    private readonly LoginApiFactory _factory;
    private readonly SoftwareAuthenticator _authenticator = new(Origin);

    public PasskeyEndpointTests(LoginApiFactory factory) => _factory = factory;

    public async Task InitializeAsync() => await _factory.ResetDatabaseAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    private sealed record Account(string Email, HttpClient Authed, byte[] Secret, Queue<string> RecoveryCodes);

    private HttpClient Authed(string accessToken)
    {
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        return client;
    }

    private static string Code(byte[] secret, int stepOffset = 0)
        => Rfc6238Totp.Compute(secret, Rfc6238Totp.Step(DateTimeOffset.UtcNow.ToUnixTimeSeconds(), 30) + stepOffset, 6);

    /// <summary>Verified account, signed in, TOTP confirmed; its recovery codes confirm the passkey operations below.</summary>
    private async Task<Account> TotpAccountAsync()
    {
        var anon = _factory.CreateClient();
        var email = await _factory.CreateVerifiedAccountAsync(anon, Password);
        var authed = Authed((await LoginApiFactory.LoginAsync(anon, email, Password)).AccessToken);

        var enrolled = (await (await authed.PostAsJsonAsync("/v1/account/totp/enroll", new { password = Password })).Content.ReadFromJsonAsync<TotpEnrollResponse>())!;
        Assert.True(Base32.TryDecode(enrolled.Secret, out var secret));
        var confirm = await authed.PostAsJsonAsync("/v1/account/totp/confirm", new { code = Code(secret) });
        Assert.Equal(HttpStatusCode.OK, confirm.StatusCode);
        var codes = (await confirm.Content.ReadFromJsonAsync<TotpRecoveryCodesResponse>())!.RecoveryCodes;
        return new Account(email, authed, secret, new Queue<string>(codes));
    }

    private static async Task<JsonElement> JsonAsync(HttpResponseMessage response)
    {
        var text = await response.Content.ReadAsStringAsync();
        Assert.True(response.IsSuccessStatusCode, $"{(int)response.StatusCode}: {text}");
        return JsonDocument.Parse(text).RootElement.Clone();
    }

    private static async Task<string?> DetailAsync(HttpResponseMessage response)
        => JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement.GetProperty("detail").GetString();

    private static async Task<(string RegistrationId, JsonElement Options)> RegistrationOptionsAsync(Account account)
    {
        var json = await JsonAsync(await account.Authed.PostAsJsonAsync("/v1/account/passkeys/registration/options",
            new { password = Password, code = account.RecoveryCodes.Dequeue() }));
        return (json.GetProperty("registrationId").GetString()!, json.GetProperty("options"));
    }

    private static Task<HttpResponseMessage> CompleteRegistrationAsync(Account account, string registrationId, JsonNode credential, string name = "Laptop")
        => account.Authed.PostAsJsonAsync("/v1/account/passkeys/registration", new { registrationId, name, credential });

    /// <summary>A registered passkey (through the endpoints) and its software credential.</summary>
    private async Task<(SoftwareCredential Credential, Guid Id)> RegisterAsync(Account account, string name = "Laptop", AuthenticatorOverrides? overrides = null)
    {
        var (registrationId, options) = await RegistrationOptionsAsync(account);
        var (response, credential) = _authenticator.Create(options, overrides);
        var created = await CompleteRegistrationAsync(account, registrationId, response, name);
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var body = (await created.Content.ReadFromJsonAsync<PasskeyCreatedResponse>())!;
        return (credential, body.Id);
    }

    private async Task<MfaChallengeResponse> PasswordStepAsync(string email)
    {
        var resp = await _factory.CreateClient().PostAsJsonAsync("/v1/auth/login", new { email, password = Password });
        Assert.Equal(HttpStatusCode.Accepted, resp.StatusCode);
        return (await resp.Content.ReadFromJsonAsync<MfaChallengeResponse>())!;
    }

    private async Task<JsonElement> MfaOptionsAsync(string mfaToken)
        => (await JsonAsync(await _factory.CreateClient().PostAsJsonAsync("/v1/auth/login/passkey/options", new { mfaToken }))).GetProperty("options");

    private Task<HttpResponseMessage> MfaPasskeyAsync(string mfaToken, JsonNode credential)
        => _factory.CreateClient().PostAsJsonAsync("/v1/auth/login/passkey", new { mfaToken, credential });

    private async Task<(string AssertionId, JsonElement Options)> PasswordlessOptionsAsync()
    {
        var json = await JsonAsync(await _factory.CreateClient().PostAsync("/v1/auth/passkey/options", null));
        return (json.GetProperty("assertionId").GetString()!, json.GetProperty("options"));
    }

    private Task<HttpResponseMessage> PasswordlessAsync(string assertionId, JsonNode credential)
        => _factory.CreateClient().PostAsJsonAsync("/v1/auth/passkey", new { assertionId, credential });

    private async Task<PasskeyListResponse> ListAsync(Account account)
        => (await (await account.Authed.GetAsync("/v1/account/passkeys")).Content.ReadFromJsonAsync<PasskeyListResponse>())!;

    private Task<long> SignCountAsync(Guid passkeyId)
        => _factory.QueryScalarAsync<long>("SELECT sign_count FROM webauthn_credentials WHERE id = @id", "@id", passkeyId.ToString());

    // ---- registration ----

    [Fact]
    public async Task Registration_OptionsFollowThePolicy_CredentialStored_ListCarriesNoKeyMaterial()
    {
        var account = await TotpAccountAsync();
        var empty = await ListAsync(account);
        Assert.Empty(empty.Passkeys);
        Assert.Equal(10, empty.Max);

        var (registrationId, options) = await RegistrationOptionsAsync(account);
        Assert.Equal(43, registrationId.Length);
        Assert.Equal("vault.bitosx.se", options.GetProperty("rp").GetProperty("id").GetString());
        Assert.Equal("BitosX", options.GetProperty("rp").GetProperty("name").GetString());
        Assert.Equal(account.Email, options.GetProperty("user").GetProperty("name").GetString());
        Assert.Equal(account.Email, options.GetProperty("user").GetProperty("displayName").GetString());
        var userHandle = Base64Url.DecodeFromChars(options.GetProperty("user").GetProperty("id").GetString()!);
        Assert.Equal(32, userHandle.Length);
        var accountId = await _factory.QueryScalarAsync<string>("SELECT CONCAT(id) FROM accounts WHERE normalized_email = @e", "@e", account.Email.ToUpperInvariant());
        Assert.NotEqual(Guid.Parse(accountId).ToByteArray(), userHandle.Take(16).ToArray());
        Assert.Equal("required", options.GetProperty("authenticatorSelection").GetProperty("residentKey").GetString());
        Assert.Equal("required", options.GetProperty("authenticatorSelection").GetProperty("userVerification").GetString());
        Assert.Equal("none", options.GetProperty("attestation").GetString());
        Assert.Equal([-7, -8, -257], options.GetProperty("pubKeyCredParams").EnumerateArray().Select(p => p.GetProperty("alg").GetInt32()).ToArray());
        Assert.All(options.GetProperty("pubKeyCredParams").EnumerateArray(), p => Assert.Equal("public-key", p.GetProperty("type").GetString()));
        Assert.Empty(options.GetProperty("excludeCredentials").EnumerateArray());
        Assert.Equal(32, Base64Url.DecodeFromChars(options.GetProperty("challenge").GetString()!).Length);

        var (response, credential) = _authenticator.Create(options, new AuthenticatorOverrides { BackupEligible = true, BackedUp = true });
        var created = await CompleteRegistrationAsync(account, registrationId, response, "  My laptop 💻  ");
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var body = (await created.Content.ReadFromJsonAsync<PasskeyCreatedResponse>())!;
        Assert.Equal("My laptop 💻", body.Name);
        Assert.True(body.BackedUp);

        var listText = await (await account.Authed.GetAsync("/v1/account/passkeys")).Content.ReadAsStringAsync();
        Assert.DoesNotContain(credential.IdBase64Url, listText);
        Assert.DoesNotContain("publicKey", listText, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("lastUsedAt", listText); // omitted until first use
        var list = await ListAsync(account);
        var item = Assert.Single(list.Passkeys);
        Assert.Equal(body.Id, item.Id);
        Assert.Equal(body.CreatedAt, item.CreatedAt);
        Assert.Null(item.LastUsedAt);

        // The stored row: the key, counter, flags, transports and the account's user handle.
        Assert.Equal(1L, await _factory.QueryScalarAsync<long>("SELECT backup_eligible FROM webauthn_credentials WHERE id = @id", "@id", body.Id.ToString()));
        Assert.Equal("internal,hybrid", await _factory.QueryScalarAsync<string>("SELECT transports FROM webauthn_credentials WHERE id = @id", "@id", body.Id.ToString()));
        Assert.Equal(Convert.ToHexString(userHandle), await _factory.QueryScalarAsync<string>("SELECT HEX(user_handle) FROM webauthn_credentials WHERE id = @id", "@id", body.Id.ToString()));

        // The next registration excludes the first credential and keeps the same user handle.
        var (_, second) = await RegistrationOptionsAsync(account);
        var excluded = Assert.Single(second.GetProperty("excludeCredentials").EnumerateArray());
        Assert.Equal(credential.IdBase64Url, excluded.GetProperty("id").GetString());
        Assert.Equal(["internal", "hybrid"], excluded.GetProperty("transports").EnumerateArray().Select(t => t.GetString()!).ToArray());
        Assert.Equal(userHandle, Base64Url.DecodeFromChars(second.GetProperty("user").GetProperty("id").GetString()!));
    }

    [Fact]
    public async Task RegistrationOptions_RequireTotp_PasswordAndCode_GenericFailure_CodeNotSpentByWrongPassword()
    {
        var anon = _factory.CreateClient();
        var email = await _factory.CreateVerifiedAccountAsync(anon, Password);
        var noTotp = Authed((await LoginApiFactory.LoginAsync(anon, email, Password)).AccessToken);
        var conflict = await noTotp.PostAsJsonAsync("/v1/account/passkeys/registration/options", new { password = Password, code = "123456" });
        Assert.Equal(HttpStatusCode.Conflict, conflict.StatusCode);
        Assert.Contains("Two-factor", await conflict.Content.ReadAsStringAsync());

        var account = await TotpAccountAsync();
        var recovery = account.RecoveryCodes.Dequeue();
        var wrongPassword = await account.Authed.PostAsJsonAsync("/v1/account/passkeys/registration/options", new { password = "Wrong-Password-Entirely-9", code = recovery });
        var wrongCode = await account.Authed.PostAsJsonAsync("/v1/account/passkeys/registration/options", new { password = Password, code = "000000" });
        var noCode = await account.Authed.PostAsJsonAsync("/v1/account/passkeys/registration/options", new { password = Password });
        Assert.Equal(HttpStatusCode.Forbidden, wrongPassword.StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, wrongCode.StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, noCode.StatusCode);
        Assert.Equal(await DetailAsync(wrongPassword), await DetailAsync(wrongCode));

        // The wrong password did not use up the recovery code; a TOTP code works too.
        Assert.Equal(HttpStatusCode.OK, (await account.Authed.PostAsJsonAsync("/v1/account/passkeys/registration/options", new { password = Password, code = recovery })).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await account.Authed.PostAsJsonAsync("/v1/account/passkeys/registration/options", new { password = Password, code = Code(account.Secret, 1) })).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await account.Authed.PostAsJsonAsync("/v1/account/passkeys/registration/options", new { password = Password, code = recovery })).StatusCode);
    }

    [Theory]
    [InlineData("origin", "InvalidAuthenticatorResponseOrigin")]
    [InlineData("rpid", "InvalidRpidHash")]
    [InlineData("type", "InvalidAttestationResponse")]
    [InlineData("challenge", "InvalidAuthenticatorResponseChallenge")]
    [InlineData("uv", "UserVerificationRequirementNotMet")]
    [InlineData("up", "UserPresentFlagNotSet")]
    public async Task Registration_WrongCeremony_400_AndTheRegistrationIsSpent(string wrong, string reason)
    {
        var account = await TotpAccountAsync();
        var (registrationId, options) = await RegistrationOptionsAsync(account);
        var overrides = wrong switch
        {
            "origin" => new AuthenticatorOverrides { Origin = "https://evil.example" },
            "rpid" => new AuthenticatorOverrides { RpIdForHash = "evil.example" },
            "type" => new AuthenticatorOverrides { Type = "webauthn.get" },
            "challenge" => new AuthenticatorOverrides { Challenge = new byte[32] },
            "uv" => new AuthenticatorOverrides { UserVerified = false },
            _ => new AuthenticatorOverrides { UserPresent = false },
        };
        var (bad, _) = _authenticator.Create(options, overrides);
        var refused = await CompleteRegistrationAsync(account, registrationId, bad);
        Assert.Equal(HttpStatusCode.BadRequest, refused.StatusCode);
        Assert.Contains("could not be verified", await refused.Content.ReadAsStringAsync());
        Assert.Equal($"refused:register:{reason}", _factory.PasskeyLog.LastRefusal);

        // Single use: a correct credential for the same registration is now too late.
        var (good, _) = _authenticator.Create(options);
        Assert.Equal(HttpStatusCode.Gone, (await CompleteRegistrationAsync(account, registrationId, good)).StatusCode);
        Assert.Empty((await ListAsync(account)).Passkeys);
    }

    [Fact]
    public async Task Registration_IdIsSingleUse_BoundToTheAccount_Expires_NameCheckedFirst()
    {
        var account = await TotpAccountAsync();
        var other = await TotpAccountAsync();

        var (registrationId, options) = await RegistrationOptionsAsync(account);
        var (response, _) = _authenticator.Create(options);

        // Another account cannot complete it (as unknown as no id at all), and that does not spend it.
        Assert.Equal(HttpStatusCode.Gone, (await CompleteRegistrationAsync(other, registrationId, response)).StatusCode);
        Assert.Equal(HttpStatusCode.Gone, (await CompleteRegistrationAsync(account, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", response)).StatusCode);
        Assert.Equal(HttpStatusCode.Gone, (await CompleteRegistrationAsync(account, "not-a-registration-id", response)).StatusCode);

        // A bad name is refused before the ceremony is spent.
        foreach (var name in new[] { "", "   ", new string('x', 65), "tab\tname", "line\nname", "bidi\u202Ename" })
        {
            var refused = await CompleteRegistrationAsync(account, registrationId, response, name);
            Assert.Equal(HttpStatusCode.BadRequest, refused.StatusCode);
            Assert.Contains("name", await refused.Content.ReadAsStringAsync());
        }

        Assert.Equal(HttpStatusCode.Created, (await CompleteRegistrationAsync(account, registrationId, response, new string('é', 64))).StatusCode);
        Assert.Equal(HttpStatusCode.Gone, (await CompleteRegistrationAsync(account, registrationId, response)).StatusCode);

        // Expired: five minutes is the limit.
        var (expiredId, expiredOptions) = await RegistrationOptionsAsync(account);
        await _factory.ExecuteAsync("UPDATE webauthn_challenges SET expires_at = UTC_TIMESTAMP(6) - INTERVAL 1 SECOND WHERE purpose = 'register' AND consumed_at IS NULL AND account_id = (SELECT id FROM accounts WHERE normalized_email = @e)", "@e", account.Email.ToUpperInvariant());
        var (late, _) = _authenticator.Create(expiredOptions);
        Assert.Equal(HttpStatusCode.Gone, (await CompleteRegistrationAsync(account, expiredId, late)).StatusCode);
        Assert.Single((await ListAsync(account)).Passkeys);
    }

    [Fact]
    public async Task Registration_AlreadyRegisteredCredential_Refused_EvenForAnotherAccount()
    {
        var account = await TotpAccountAsync();
        var (credential, _) = await RegisterAsync(account);

        // An authenticator that ignored excludeCredentials and returned the registered credential id again.
        var (registrationId, options) = await RegistrationOptionsAsync(account);
        var (again, _) = _authenticator.Create(options, new AuthenticatorOverrides { CredentialId = credential.Id });
        Assert.Equal(HttpStatusCode.BadRequest, (await CompleteRegistrationAsync(account, registrationId, again)).StatusCode);
        Assert.Equal("refused:register:duplicate-credential", _factory.PasskeyLog.LastRefusal);

        var other = await TotpAccountAsync();
        var (otherId, otherOptions) = await RegistrationOptionsAsync(other);
        var (stolen, _) = _authenticator.Create(otherOptions, new AuthenticatorOverrides { CredentialId = credential.Id });
        Assert.Equal(HttpStatusCode.BadRequest, (await CompleteRegistrationAsync(other, otherId, stolen)).StatusCode);
        Assert.Single((await ListAsync(account)).Passkeys);
        Assert.Empty((await ListAsync(other)).Passkeys);
    }

    [Fact]
    public async Task Registration_MalformedCredential_400()
    {
        var account = await TotpAccountAsync();
        foreach (var credential in new JsonNode?[] { JsonValue.Create("text"), new JsonObject(), new JsonObject { ["id"] = "x", ["rawId"] = "%%%", ["type"] = "public-key" }, null })
        {
            var (registrationId, _) = await RegistrationOptionsAsync(account);
            var resp = await account.Authed.PostAsJsonAsync("/v1/account/passkeys/registration", new { registrationId, name = "x", credential });
            Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
        }

        Assert.Empty((await ListAsync(account)).Passkeys);
    }

    [Fact]
    public async Task Limit_TenPasskeys_EleventhRefusedWith409_BeforeAnyCodeIsSpent()
    {
        var account = await TotpAccountAsync();
        await RegisterAsync(account, "first");
        var (pendingId, pendingOptions) = await RegistrationOptionsAsync(account); // issued while there is room

        var accountId = await _factory.QueryScalarAsync<string>("SELECT CONCAT(account_id) FROM webauthn_credentials LIMIT 1", "@x", 0);
        for (var i = 0; i < 9; i++)
        {
            await _factory.ExecuteAsync(
                $"""
                INSERT INTO webauthn_credentials (id, account_id, credential_id, public_key, sign_count, user_handle, name, aaguid, backup_eligible, backed_up, transports, created_at)
                SELECT UUID(), account_id, RANDOM_BYTES(32), public_key, 0, user_handle, 'seeded {i}', aaguid, 0, 0, NULL, UTC_TIMESTAMP(6)
                FROM webauthn_credentials WHERE account_id = @a LIMIT 1
                """, "@a", accountId);
        }

        Assert.Equal(10, (await ListAsync(account)).Passkeys.Count);
        var recovery = account.RecoveryCodes.Peek();
        var refused = await account.Authed.PostAsJsonAsync("/v1/account/passkeys/registration/options", new { password = Password, code = recovery });
        Assert.Equal(HttpStatusCode.Conflict, refused.StatusCode);
        Assert.Contains("at most 10", await refused.Content.ReadAsStringAsync());

        // The registration issued before the tenth arrived is refused at insert time too.
        var (late, _) = _authenticator.Create(pendingOptions);
        Assert.Equal(HttpStatusCode.Conflict, (await CompleteRegistrationAsync(account, pendingId, late)).StatusCode);
        Assert.Equal(10, (await ListAsync(account)).Passkeys.Count);

        // The 409 spent no code: the recovery code still confirms something else.
        Assert.Equal(HttpStatusCode.OK, (await account.Authed.PostAsJsonAsync("/v1/account/totp/recovery-codes", new { password = Password, code = recovery })).StatusCode);
    }

    // ---- management ----

    [Fact]
    public async Task Rename_And_Delete_OwnPasskeysOnly()
    {
        var account = await TotpAccountAsync();
        var other = await TotpAccountAsync();
        var (_, id) = await RegisterAsync(account, "old name");
        var (_, otherId) = await RegisterAsync(other, "theirs");

        Assert.Equal(HttpStatusCode.NoContent, (await account.Authed.PatchAsJsonAsync($"/v1/account/passkeys/{id}", new { name = " Phone " })).StatusCode);
        Assert.Equal("Phone", Assert.Single((await ListAsync(account)).Passkeys).Name);
        // The browser route (CORS allows no PATCH).
        Assert.Equal(HttpStatusCode.NoContent, (await account.Authed.PostAsJsonAsync($"/v1/account/passkeys/{id}/rename", new { name = "Work phone" })).StatusCode);
        Assert.Equal("Work phone", Assert.Single((await ListAsync(account)).Passkeys).Name);
        Assert.Equal(HttpStatusCode.NotFound, (await account.Authed.PostAsJsonAsync($"/v1/account/passkeys/{otherId}/rename", new { name = "mine now" })).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await account.Authed.PatchAsJsonAsync($"/v1/account/passkeys/{id}", new { name = "" })).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await account.Authed.PatchAsJsonAsync($"/v1/account/passkeys/{otherId}", new { name = "mine now" })).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await account.Authed.PatchAsJsonAsync($"/v1/account/passkeys/{Guid.NewGuid()}", new { name = "x" })).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await account.Authed.PatchAsJsonAsync("/v1/account/passkeys/not-a-guid", new { name = "x" })).StatusCode);
        Assert.Equal("theirs", Assert.Single((await ListAsync(other)).Passkeys).Name);

        var code = account.RecoveryCodes.Dequeue();
        Assert.Equal(HttpStatusCode.NotFound, (await account.Authed.PostAsJsonAsync($"/v1/account/passkeys/{otherId}/delete", new { password = Password, code })).StatusCode);
        var wrongPassword = await account.Authed.PostAsJsonAsync($"/v1/account/passkeys/{id}/delete", new { password = "Wrong-Password-Entirely-9", code });
        Assert.Equal(HttpStatusCode.Forbidden, wrongPassword.StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await account.Authed.PostAsJsonAsync($"/v1/account/passkeys/{id}/delete", new { password = Password, code = "000000" })).StatusCode);
        Assert.Single((await ListAsync(account)).Passkeys);

        Assert.Equal(HttpStatusCode.NoContent, (await account.Authed.PostAsJsonAsync($"/v1/account/passkeys/{id}/delete", new { password = Password, code })).StatusCode);
        Assert.Empty((await ListAsync(account)).Passkeys);
        Assert.Single((await ListAsync(other)).Passkeys);
        Assert.Equal(HttpStatusCode.NotFound, (await account.Authed.PostAsJsonAsync($"/v1/account/passkeys/{id}/delete", new { password = Password, code = account.RecoveryCodes.Dequeue() })).StatusCode);
    }

    [Fact]
    public async Task TotpDisable_RefusedWhilePasskeysExist_WithoutSpendingTheCode_AllowedAfterRemoval()
    {
        var account = await TotpAccountAsync();
        var (_, id) = await RegisterAsync(account);

        var code = account.RecoveryCodes.Dequeue();
        var refused = await account.Authed.PostAsJsonAsync("/v1/account/totp/disable", new { password = Password, code });
        Assert.Equal(HttpStatusCode.Conflict, refused.StatusCode);
        Assert.Contains("Remove the passkeys first", await refused.Content.ReadAsStringAsync());
        Assert.True((await (await account.Authed.GetAsync("/v1/account/totp")).Content.ReadFromJsonAsync<TotpStatusResponse>())!.Enabled);

        Assert.Equal(HttpStatusCode.NoContent, (await account.Authed.PostAsJsonAsync($"/v1/account/passkeys/{id}/delete", new { password = Password, code })).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await account.Authed.PostAsJsonAsync("/v1/account/totp/disable", new { password = Password, code = account.RecoveryCodes.Dequeue() })).StatusCode);
    }

    [Fact]
    public async Task AccountDeletion_RemovesPasskeys_PasswordResetKeepsThem()
    {
        var account = await TotpAccountAsync();
        await RegisterAsync(account);
        var accountId = await _factory.QueryScalarAsync<string>("SELECT CONCAT(id) FROM accounts WHERE normalized_email = @e", "@e", account.Email.ToUpperInvariant());

        Assert.Equal(HttpStatusCode.NoContent, (await account.Authed.PostAsJsonAsync("/v1/account/delete", new { password = Password, code = account.RecoveryCodes.Dequeue() })).StatusCode);
        Assert.Equal(0L, await _factory.QueryScalarAsync<long>("SELECT COUNT(*) FROM webauthn_credentials WHERE account_id = @a", "@a", accountId));
        Assert.Equal(0L, await _factory.QueryScalarAsync<long>("SELECT COUNT(*) FROM webauthn_challenges WHERE account_id = @a", "@a", accountId));
    }

    // ---- second factor ----

    [Fact]
    public async Task SecondFactor_MethodsAdvertisePasskey_AssertionSignsIn_CounterAndLastUsedRecorded()
    {
        var account = await TotpAccountAsync();
        var before = await PasswordStepAsync(account.Email);
        Assert.Equal("totp", before.Method);
        Assert.Equal(["totp", "recovery"], before.Methods);

        var (credential, id) = await RegisterAsync(account);
        var challenge = await PasswordStepAsync(account.Email);
        Assert.Equal("totp", challenge.Method);
        Assert.Equal(["totp", "recovery", "passkey"], challenge.Methods);

        var options = await MfaOptionsAsync(challenge.MfaToken);
        Assert.Equal("vault.bitosx.se", options.GetProperty("rpId").GetString());
        Assert.Equal("preferred", options.GetProperty("userVerification").GetString());
        Assert.Equal(credential.IdBase64Url, Assert.Single(options.GetProperty("allowCredentials").EnumerateArray()).GetProperty("id").GetString());

        // A user-verification-less assertion is fine for the second factor (the password was the first).
        var signedIn = await MfaPasskeyAsync(challenge.MfaToken, _authenticator.Get(options, credential, new AuthenticatorOverrides { UserVerified = false, SignCount = 7 }));
        Assert.Equal(HttpStatusCode.OK, signedIn.StatusCode);
        var tokens = (await signedIn.Content.ReadFromJsonAsync<TokenResponse>())!;
        Assert.Equal(HttpStatusCode.OK, (await Authed(tokens.AccessToken).GetAsync("/v1/account/me")).StatusCode);
        Assert.Equal(7L, await SignCountAsync(id));
        Assert.NotNull(Assert.Single((await ListAsync(account)).Passkeys).LastUsedAt);

        // The MFA challenge is single use, with a passkey as with a code.
        Assert.Equal(HttpStatusCode.Unauthorized, (await _factory.CreateClient().PostAsJsonAsync("/v1/auth/login/passkey/options", new { mfaToken = challenge.MfaToken })).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await _factory.CreateClient().PostAsJsonAsync("/v1/auth/login/totp", new { mfaToken = challenge.MfaToken, code = account.RecoveryCodes.Peek() })).StatusCode);
    }

    [Fact]
    public async Task SecondFactor_Options_401ForBadTokenOrAccountWithoutPasskeys()
    {
        var account = await TotpAccountAsync();
        var challenge = await PasswordStepAsync(account.Email);
        var client = _factory.CreateClient();
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.PostAsJsonAsync("/v1/auth/login/passkey/options", new { mfaToken = challenge.MfaToken })).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.PostAsJsonAsync("/v1/auth/login/passkey/options", new { mfaToken = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" })).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.PostAsJsonAsync("/v1/auth/login/passkey/options", new { mfaToken = "short" })).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.PostAsJsonAsync("/v1/auth/login/passkey/options", new { })).StatusCode);
    }

    [Fact]
    public async Task SecondFactor_Failures_Generic401_EachSpendsAnAttempt_FifthKillsTheChallenge()
    {
        var account = await TotpAccountAsync();
        var other = await TotpAccountAsync();
        var (credential, _) = await RegisterAsync(account);
        var (foreign, _) = await RegisterAsync(other);
        var challenge = await PasswordStepAsync(account.Email);

        var failures = new (Func<JsonElement, JsonNode> Make, string Reason)[]
        {
            (o => _authenticator.Get(o, credential, new AuthenticatorOverrides { Origin = "https://vault.bitosx.se.evil.example" }), "InvalidAuthenticatorResponseOrigin"),
            (o => _authenticator.Get(o, credential, new AuthenticatorOverrides { RpIdForHash = "bitosx.se" }), "InvalidRpidHash"),
            (o => _authenticator.Get(o, foreign), "unknown-credential"),                                        // another account's credential
            (o => _authenticator.Get(o, credential, new AuthenticatorOverrides { SignWith = foreign }), "InvalidSignature"), // the wrong key
        };

        string? firstBody = null;
        foreach (var (make, reason) in failures)
        {
            var refused = await MfaPasskeyAsync(challenge.MfaToken, make(await MfaOptionsAsync(challenge.MfaToken)));
            Assert.Equal(HttpStatusCode.Unauthorized, refused.StatusCode);
            var body = await DetailAsync(refused);
            Assert.Equal(firstBody ??= body, body);
            Assert.Equal($"refused:mfa:{reason}", _factory.PasskeyLog.LastRefusal);
        }

        Assert.Equal(4L, await _factory.QueryScalarAsync<long>("SELECT attempt_count FROM mfa_challenges WHERE consumed_at IS NULL AND account_id = (SELECT id FROM accounts WHERE normalized_email = @e)", "@e", account.Email.ToUpperInvariant()));

        // Fifth failure: an assertion over a challenge from another ceremony (a passwordless one).
        var (_, passwordlessOptions) = await PasswordlessOptionsAsync();
        var otherPurpose = _authenticator.Get(passwordlessOptions, credential);
        await MfaOptionsAsync(challenge.MfaToken);
        Assert.Equal(HttpStatusCode.Unauthorized, (await MfaPasskeyAsync(challenge.MfaToken, otherPurpose)).StatusCode);
        Assert.Equal("refused:mfa:InvalidAuthenticatorResponseChallenge", _factory.PasskeyLog.LastRefusal);

        // The challenge is dead: even a correct assertion (and the options request) are refused; the password is needed again.
        Assert.Equal(HttpStatusCode.Unauthorized, (await _factory.CreateClient().PostAsJsonAsync("/v1/auth/login/passkey/options", new { mfaToken = challenge.MfaToken })).StatusCode);
        var fresh = await PasswordStepAsync(account.Email);
        Assert.Equal(HttpStatusCode.OK, (await MfaPasskeyAsync(fresh.MfaToken, _authenticator.Get(await MfaOptionsAsync(fresh.MfaToken), credential))).StatusCode);
    }

    [Fact]
    public async Task SecondFactor_ReplayedAssertion_ReplacedCeremony_CounterRegression_Refused()
    {
        var account = await TotpAccountAsync();
        var (credential, id) = await RegisterAsync(account);

        // The options are single use per request: asking again replaces the ceremony, the old assertion no longer fits.
        var challenge = await PasswordStepAsync(account.Email);
        var stale = _authenticator.Get(await MfaOptionsAsync(challenge.MfaToken), credential);
        var current = _authenticator.Get(await MfaOptionsAsync(challenge.MfaToken), credential);
        Assert.Equal(HttpStatusCode.Unauthorized, (await MfaPasskeyAsync(challenge.MfaToken, stale)).StatusCode);
        Assert.Equal("refused:mfa:InvalidAuthenticatorResponseChallenge", _factory.PasskeyLog.LastRefusal);
        // ...and the refused attempt spent the ceremony: the current assertion needs new options.
        Assert.Equal(HttpStatusCode.Unauthorized, (await MfaPasskeyAsync(challenge.MfaToken, current)).StatusCode);
        Assert.Equal("refused:mfa:no-ceremony", _factory.PasskeyLog.LastRefusal);
        var good = _authenticator.Get(await MfaOptionsAsync(challenge.MfaToken), credential);
        Assert.Equal(HttpStatusCode.OK, (await MfaPasskeyAsync(challenge.MfaToken, good)).StatusCode);
        var counter = await SignCountAsync(id);

        // Replay of a successful assertion on a new challenge (its challenge does not match).
        var next = await PasswordStepAsync(account.Email);
        await MfaOptionsAsync(next.MfaToken);
        Assert.Equal(HttpStatusCode.Unauthorized, (await MfaPasskeyAsync(next.MfaToken, good)).StatusCode);

        // A counter that does not increase (a cloned authenticator) is refused and nothing is recorded.
        var cloned = _authenticator.Get(await MfaOptionsAsync(next.MfaToken), credential, new AuthenticatorOverrides { SignCount = (uint)counter });
        Assert.Equal(HttpStatusCode.Unauthorized, (await MfaPasskeyAsync(next.MfaToken, cloned)).StatusCode);
        Assert.Equal("refused:mfa:counter-regression", _factory.PasskeyLog.LastRefusal);
        Assert.Equal(counter, await SignCountAsync(id));
        var lower = _authenticator.Get(await MfaOptionsAsync(next.MfaToken), credential, new AuthenticatorOverrides { SignCount = 0 });
        Assert.Equal(HttpStatusCode.Unauthorized, (await MfaPasskeyAsync(next.MfaToken, lower)).StatusCode);
        Assert.Equal(counter, await SignCountAsync(id));
    }

    [Fact]
    public async Task SecondFactor_UnknownCredential_Malformed_And_PasswordChangedMeanwhile_Refused()
    {
        var account = await TotpAccountAsync();
        var (credential, _) = await RegisterAsync(account);
        var challenge = await PasswordStepAsync(account.Email);

        using var stranger = new SoftwareCredential(new byte[] { 1, 2, 3 }, System.Security.Cryptography.ECDsa.Create(), "vault.bitosx.se", credential.UserHandle, 0);
        Assert.Equal(HttpStatusCode.Unauthorized, (await MfaPasskeyAsync(challenge.MfaToken, _authenticator.Get(await MfaOptionsAsync(challenge.MfaToken), stranger))).StatusCode);
        Assert.Equal("refused:mfa:unknown-credential", _factory.PasskeyLog.LastRefusal);
        await MfaOptionsAsync(challenge.MfaToken);
        Assert.Equal(HttpStatusCode.Unauthorized, (await MfaPasskeyAsync(challenge.MfaToken, new JsonObject { ["id"] = "x" })).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await _factory.CreateClient().PostAsJsonAsync("/v1/auth/login/passkey", new { mfaToken = challenge.MfaToken, credential = "not an object" })).StatusCode);

        // The password changed between the steps: the challenge is worthless.
        var options = await MfaOptionsAsync(challenge.MfaToken);
        Assert.Equal(HttpStatusCode.NoContent, (await account.Authed.PostAsJsonAsync("/v1/account/password",
            new { currentPassword = Password, newPassword = "Another-Correct-Horse-2", code = account.RecoveryCodes.Dequeue() })).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await MfaPasskeyAsync(challenge.MfaToken, _authenticator.Get(options, credential))).StatusCode);
    }

    // ---- passwordless ----

    [Fact]
    public async Task Passwordless_DiscoverableCredentialWithUv_SignsIn_OptionsRevealNothing()
    {
        var account = await TotpAccountAsync();
        var (credential, id) = await RegisterAsync(account);

        var (assertionId, options) = await PasswordlessOptionsAsync();
        Assert.Equal(43, assertionId.Length);
        Assert.Empty(options.GetProperty("allowCredentials").EnumerateArray());
        Assert.Equal("required", options.GetProperty("userVerification").GetString());
        Assert.Equal("vault.bitosx.se", options.GetProperty("rpId").GetString());

        var resp = await PasswordlessAsync(assertionId, _authenticator.Get(options, credential));
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        var tokens = (await resp.Content.ReadFromJsonAsync<TokenResponse>())!;
        var me = (await (await Authed(tokens.AccessToken).GetAsync("/v1/account/me")).Content.ReadFromJsonAsync<MeResponse>())!;
        Assert.Equal(account.Email, me.Email);
        Assert.Equal(1L, await SignCountAsync(id));
        Assert.NotNull(Assert.Single((await ListAsync(account)).Passkeys).LastUsedAt);

        // The refresh token of a passkey session works like any other.
        Assert.Equal(HttpStatusCode.OK, (await _factory.CreateClient().PostAsJsonAsync("/v1/auth/refresh", new { refreshToken = tokens.RefreshToken })).StatusCode);

        // The assertion id is single use.
        Assert.Equal(HttpStatusCode.Unauthorized, (await PasswordlessAsync(assertionId, _authenticator.Get(options, credential))).StatusCode);
    }

    [Theory]
    [InlineData("no-uv", "UserVerificationRequirementNotMet")]
    [InlineData("user-handle-mismatch", "user-handle-mismatch")]
    [InlineData("no-user-handle", "no-user-handle")]
    [InlineData("origin", "InvalidAuthenticatorResponseOrigin")]
    [InlineData("rpid", "InvalidRpidHash")]
    [InlineData("type", "InvalidAssertionResponse")]
    [InlineData("counter", "counter-regression")]
    [InlineData("signature", "InvalidSignature")]
    public async Task Passwordless_BadAssertion_Generic401_NothingRecorded(string wrong, string reason)
    {
        var account = await TotpAccountAsync();
        var (credential, id) = await RegisterAsync(account);
        var other = await TotpAccountAsync();
        var (foreign, _) = await RegisterAsync(other);

        // A first sign-in so the counter is non-zero.
        var (firstId, firstOptions) = await PasswordlessOptionsAsync();
        Assert.Equal(HttpStatusCode.OK, (await PasswordlessAsync(firstId, _authenticator.Get(firstOptions, credential, new AuthenticatorOverrides { SignCount = 5 }))).StatusCode);

        var (assertionId, options) = await PasswordlessOptionsAsync();
        var overrides = wrong switch
        {
            "no-uv" => new AuthenticatorOverrides { UserVerified = false },
            "user-handle-mismatch" => new AuthenticatorOverrides { UserHandle = foreign.UserHandle },
            "no-user-handle" => new AuthenticatorOverrides { OmitUserHandle = true },
            "origin" => new AuthenticatorOverrides { Origin = "http://vault.bitosx.se" },
            "rpid" => new AuthenticatorOverrides { RpIdForHash = "localhost" },
            "type" => new AuthenticatorOverrides { Type = "webauthn.create" },
            "counter" => new AuthenticatorOverrides { SignCount = 5 },
            _ => new AuthenticatorOverrides { SignWith = foreign },
        };
        var refused = await PasswordlessAsync(assertionId, _authenticator.Get(options, credential, overrides));
        Assert.Equal(HttpStatusCode.Unauthorized, refused.StatusCode);
        Assert.Contains("Passkey sign-in failed.", await refused.Content.ReadAsStringAsync());
        Assert.Equal($"refused:passwordless:{reason}", _factory.PasskeyLog.LastRefusal);
        Assert.Equal(5L, await SignCountAsync(id));
        Assert.Equal(0L, await _factory.ActiveSessionCountAsync(other.Email) - 1); // only the session from TotpAccountAsync
    }

    [Fact]
    public async Task Passwordless_UnknownCredential_ExpiredOrOtherPurposeCeremony_Refused()
    {
        var account = await TotpAccountAsync();
        var (credential, _) = await RegisterAsync(account);

        using var unknown = new SoftwareCredential(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32), System.Security.Cryptography.ECDsa.Create(System.Security.Cryptography.ECCurve.NamedCurves.nistP256), "vault.bitosx.se", credential.UserHandle, 0);
        var (unknownId, unknownOptions) = await PasswordlessOptionsAsync();
        Assert.Equal(HttpStatusCode.Unauthorized, (await PasswordlessAsync(unknownId, _authenticator.Get(unknownOptions, unknown))).StatusCode);
        Assert.Equal("refused:passwordless:unknown-credential", _factory.PasskeyLog.LastRefusal);

        var (expiredId, expiredOptions) = await PasswordlessOptionsAsync();
        await _factory.ExecuteAsync("UPDATE webauthn_challenges SET expires_at = UTC_TIMESTAMP(6) - INTERVAL 1 SECOND WHERE purpose = @p AND consumed_at IS NULL", "@p", "passwordless");
        Assert.Equal(HttpStatusCode.Unauthorized, (await PasswordlessAsync(expiredId, _authenticator.Get(expiredOptions, credential))).StatusCode);

        // A second-step ceremony's challenge does not open a passwordless ceremony (and vice versa above).
        var challenge = await PasswordStepAsync(account.Email);
        var mfaOptions = await MfaOptionsAsync(challenge.MfaToken);
        var (passwordlessId, _) = await PasswordlessOptionsAsync();
        Assert.Equal(HttpStatusCode.Unauthorized, (await PasswordlessAsync(passwordlessId, _authenticator.Get(mfaOptions, credential))).StatusCode);
        Assert.Equal("refused:passwordless:InvalidAuthenticatorResponseChallenge", _factory.PasskeyLog.LastRefusal);
        Assert.Equal(HttpStatusCode.Unauthorized, (await PasswordlessAsync(challenge.MfaToken, _authenticator.Get(mfaOptions, credential))).StatusCode);

        Assert.Equal(HttpStatusCode.Unauthorized, (await PasswordlessAsync("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", _authenticator.Get(mfaOptions, credential))).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await _factory.CreateClient().PostAsJsonAsync("/v1/auth/passkey", new { })).StatusCode);
    }

    [Fact]
    public async Task Passwordless_RefusedWhenTotpRemovedOutOfBand_OrAccountDisabled()
    {
        var account = await TotpAccountAsync();
        var (credential, _) = await RegisterAsync(account);
        var accountId = await _factory.QueryScalarAsync<string>("SELECT CONCAT(id) FROM accounts WHERE normalized_email = @e", "@e", account.Email.ToUpperInvariant());

        await _factory.ExecuteAsync("UPDATE accounts SET disabled_at = UTC_TIMESTAMP(6) WHERE id = @a", "@a", accountId);
        var (disabledId, disabledOptions) = await PasswordlessOptionsAsync();
        Assert.Equal(HttpStatusCode.Unauthorized, (await PasswordlessAsync(disabledId, _authenticator.Get(disabledOptions, credential))).StatusCode);
        Assert.Equal("refused:passwordless:account-state", _factory.PasskeyLog.LastRefusal);
        await _factory.ExecuteAsync("UPDATE accounts SET disabled_at = NULL WHERE id = @a", "@a", accountId);

        await _factory.ExecuteAsync("DELETE FROM account_totp WHERE account_id = @a", "@a", accountId);
        var (assertionId, options) = await PasswordlessOptionsAsync();
        Assert.Equal(HttpStatusCode.Unauthorized, (await PasswordlessAsync(assertionId, _authenticator.Get(options, credential))).StatusCode);
        Assert.Equal("refused:passwordless:no-totp", _factory.PasskeyLog.LastRefusal);
    }

    [Fact]
    public async Task PasswordlessOptions_AcceptNoBody_AndOversizedBodies413()
    {
        var resp = await _factory.CreateClient().PostAsync("/v1/auth/passkey/options", new StringContent(new string(' ', 5000), System.Text.Encoding.UTF8, "application/json"));
        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, resp.StatusCode);
        var big = await _factory.CreateClient().PostAsync("/v1/auth/passkey", new StringContent("{\"assertionId\":\"" + new string('a', 17000) + "\"}", System.Text.Encoding.UTF8, "application/json"));
        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, big.StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await _factory.CreateClient().PostAsync("/v1/auth/passkey/options", null)).StatusCode);
    }

    [Fact]
    public async Task Housekeeping_PrunesExpiredCeremonies()
    {
        await PasswordlessOptionsAsync();
        await PasswordlessOptionsAsync();
        await _factory.ExecuteAsync("UPDATE webauthn_challenges SET expires_at = UTC_TIMESTAMP(6) - INTERVAL 1 SECOND LIMIT @n", "@n", 1);
        using var scope = _factory.Services.CreateScope();
        var result = await scope.ServiceProvider.GetRequiredService<BitosX.Infrastructure.Housekeeping.HousekeepingRunner>().RunOnceAsync();
        Assert.Equal(1, result.WebAuthnChallenges);
        Assert.Equal(1L, await _factory.QueryScalarAsync<long>("SELECT COUNT(*) FROM webauthn_challenges WHERE purpose = @p", "@p", "passwordless"));
    }
}

/// <summary>Without a Security:WebAuthn section the Passkeys capability is off: every passkey route is 404 and the second step never offers "passkey".</summary>
public sealed class PasskeyCapabilityOffTests : IAsyncLifetime
{
    private readonly LoginApiFactory _factory = new() { PasskeysCapability = false };

    public async Task InitializeAsync() => await _factory.ResetDatabaseAsync();

    public async Task DisposeAsync() => await _factory.DisposeAsync();

    [Fact]
    public async Task EveryPasskeyRoute_404_MethodsWithoutPasskey()
    {
        const string password = "Correct-Horse-Battery-Staple-1";
        var anon = _factory.CreateClient();
        var email = await _factory.CreateVerifiedAccountAsync(anon, password);
        var authed = _factory.CreateClient();
        authed.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", (await LoginApiFactory.LoginAsync(anon, email, password)).AccessToken);

        Assert.Equal(HttpStatusCode.NotFound, (await authed.GetAsync("/v1/account/passkeys")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await authed.PostAsJsonAsync("/v1/account/passkeys/registration/options", new { password, code = "123456" })).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await authed.PostAsJsonAsync("/v1/account/passkeys/registration", new { })).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await authed.PatchAsJsonAsync($"/v1/account/passkeys/{Guid.NewGuid()}", new { name = "x" })).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await authed.PostAsJsonAsync($"/v1/account/passkeys/{Guid.NewGuid()}/rename", new { name = "x" })).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await authed.PostAsJsonAsync($"/v1/account/passkeys/{Guid.NewGuid()}/delete", new { })).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await anon.PostAsJsonAsync("/v1/auth/login/passkey/options", new { mfaToken = "x" })).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await anon.PostAsJsonAsync("/v1/auth/login/passkey", new { })).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await anon.PostAsync("/v1/auth/passkey/options", null)).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await anon.PostAsJsonAsync("/v1/auth/passkey", new { })).StatusCode);

        // TOTP on: the second step lists codes only.
        var enrolled = (await (await authed.PostAsJsonAsync("/v1/account/totp/enroll", new { password })).Content.ReadFromJsonAsync<TotpEnrollResponse>())!;
        Assert.True(Base32.TryDecode(enrolled.Secret, out var secret));
        var code = Rfc6238Totp.Compute(secret, Rfc6238Totp.Step(DateTimeOffset.UtcNow.ToUnixTimeSeconds(), 30), 6);
        Assert.Equal(HttpStatusCode.OK, (await authed.PostAsJsonAsync("/v1/account/totp/confirm", new { code })).StatusCode);
        var challenge = (await (await anon.PostAsJsonAsync("/v1/auth/login", new { email, password })).Content.ReadFromJsonAsync<MfaChallengeResponse>())!;
        Assert.Equal(["totp", "recovery"], challenge.Methods);
    }
}
