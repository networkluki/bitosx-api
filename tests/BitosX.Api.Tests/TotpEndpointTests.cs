using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using BitosX.Application.Mfa;
using BitosX.Contracts.Accounts;

namespace BitosX.Api.Tests;

/// <summary>
/// End-to-end second factor: enroll → confirm → the password step answers 202 with a challenge → the code
/// step issues tokens; replay, wrong codes, attempt limit, recovery codes, disable, regeneration and the
/// generic failure contract. Codes are computed from the secret the enroll call returned, as an app would.
/// </summary>
public sealed class TotpEndpointTests : IClassFixture<LoginApiFactory>, IAsyncLifetime
{
    private const string Password = "Correct-Horse-Battery-Staple-1";

    private readonly LoginApiFactory _factory;

    public TotpEndpointTests(LoginApiFactory factory) => _factory = factory;

    public async Task InitializeAsync() => await _factory.ResetDatabaseAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    private HttpClient Authed(string accessToken)
    {
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        return client;
    }

    private static string Code(byte[] secret, int stepOffset = 0)
        => Rfc6238Totp.Compute(secret, Rfc6238Totp.Step(DateTimeOffset.UtcNow.ToUnixTimeSeconds(), 30) + stepOffset, 6);

    /// <summary>Verified account, signed in, TOTP enrolled and confirmed. Returns the raw secret and the recovery codes.</summary>
    private async Task<(string Email, HttpClient Authed, byte[] Secret, IReadOnlyList<string> RecoveryCodes)> EnabledAccountAsync()
    {
        var anon = _factory.CreateClient();
        var email = await _factory.CreateVerifiedAccountAsync(anon, Password);
        var login = await LoginApiFactory.LoginAsync(anon, email, Password);
        var authed = Authed(login.AccessToken);

        var enroll = await authed.PostAsJsonAsync("/v1/account/totp/enroll", new { password = Password });
        Assert.Equal(HttpStatusCode.OK, enroll.StatusCode);
        var enrolled = (await enroll.Content.ReadFromJsonAsync<TotpEnrollResponse>())!;
        Assert.True(Base32.TryDecode(enrolled.Secret, out var secret));
        Assert.Equal(20, secret.Length);
        Assert.Contains("otpauth://totp/BitosX:", enrolled.OtpauthUri);
        Assert.Contains("secret=" + enrolled.Secret, enrolled.OtpauthUri);
        Assert.Equal(email, enrolled.Label);

        var confirm = await authed.PostAsJsonAsync("/v1/account/totp/confirm", new { code = Code(secret) });
        Assert.Equal(HttpStatusCode.OK, confirm.StatusCode);
        var codes = (await confirm.Content.ReadFromJsonAsync<TotpRecoveryCodesResponse>())!.RecoveryCodes;
        Assert.Equal(10, codes.Count);
        return (email, authed, secret, codes);
    }

    private async Task<MfaChallengeResponse> PasswordStepAsync(HttpClient client, string email)
    {
        var resp = await client.PostAsJsonAsync("/v1/auth/login", new { email, password = Password });
        Assert.Equal(HttpStatusCode.Accepted, resp.StatusCode);
        var body = await resp.Content.ReadAsStringAsync();
        Assert.DoesNotContain("accessToken", body);
        Assert.DoesNotContain("refreshToken", body);
        return (await resp.Content.ReadFromJsonAsync<MfaChallengeResponse>())!;
    }

    [Fact]
    public async Task Status_BeforeAndAfter_AndEnrollNeedsCorrectPassword()
    {
        var anon = _factory.CreateClient();
        var email = await _factory.CreateVerifiedAccountAsync(anon, Password);
        var authed = Authed((await LoginApiFactory.LoginAsync(anon, email, Password)).AccessToken);

        var before = await (await authed.GetAsync("/v1/account/totp")).Content.ReadFromJsonAsync<TotpStatusResponse>();
        Assert.Equal(new TotpStatusResponse(false, null, 0, false), before);

        Assert.Equal(HttpStatusCode.Forbidden, (await authed.PostAsJsonAsync("/v1/account/totp/enroll", new { password = "Wrong-Password-Entirely-9" })).StatusCode);
        Assert.Equal(new TotpStatusResponse(false, null, 0, false), await (await authed.GetAsync("/v1/account/totp")).Content.ReadFromJsonAsync<TotpStatusResponse>());

        Assert.Equal(HttpStatusCode.Conflict, (await authed.PostAsJsonAsync("/v1/account/totp/confirm", new { code = "123456" })).StatusCode); // nothing pending

        (await authed.PostAsJsonAsync("/v1/account/totp/enroll", new { password = Password })).EnsureSuccessStatusCode();
        var pending = await (await authed.GetAsync("/v1/account/totp")).Content.ReadFromJsonAsync<TotpStatusResponse>();
        Assert.Equal(new TotpStatusResponse(false, null, 0, true), pending);

        // Pending enrollment is not a second factor: login still issues tokens directly.
        Assert.Equal(HttpStatusCode.OK, (await anon.PostAsJsonAsync("/v1/auth/login", new { email, password = Password })).StatusCode);

        Assert.Equal(HttpStatusCode.BadRequest, (await authed.PostAsJsonAsync("/v1/account/totp/confirm", new { code = "000000" })).StatusCode);
    }

    [Fact]
    public async Task FullFlow_PasswordStep202_CodeStepTokens_ReplayRejected_StatusEnabled()
    {
        var (email, authed, secret, recoveryCodes) = await EnabledAccountAsync();
        var anon = _factory.CreateClient();

        var status = await (await authed.GetAsync("/v1/account/totp")).Content.ReadFromJsonAsync<TotpStatusResponse>();
        Assert.True(status!.Enabled);
        Assert.Equal(10, status.RecoveryCodesRemaining);
        Assert.Equal(HttpStatusCode.Conflict, (await authed.PostAsJsonAsync("/v1/account/totp/enroll", new { password = Password })).StatusCode);

        var challenge = await PasswordStepAsync(anon, email);
        Assert.Equal(43, challenge.MfaToken.Length);
        Assert.Equal("totp", challenge.Method);
        Assert.True(challenge.MfaTokenExpiresAt > DateTime.UtcNow);
        // No session was created by the password step.
        Assert.Equal(1L, await _factory.ActiveSessionCountAsync(email)); // only the one from EnabledAccountAsync

        // The confirmation already used the current step; the next step is what a real app shows next.
        var code = Code(secret, 1);
        var step2 = await anon.PostAsJsonAsync("/v1/auth/login/totp", new { mfaToken = challenge.MfaToken, code });
        Assert.Equal(HttpStatusCode.OK, step2.StatusCode);
        var tokens = (await step2.Content.ReadFromJsonAsync<TokenResponse>())!;
        Assert.Equal(3, tokens.AccessToken.Split('.').Length);
        Assert.Equal(HttpStatusCode.OK, (await Authed(tokens.AccessToken).GetAsync("/v1/account/me")).StatusCode);
        Assert.Equal(2L, await _factory.ActiveSessionCountAsync(email));

        // The challenge token is single use.
        Assert.Equal(HttpStatusCode.Unauthorized, (await anon.PostAsJsonAsync("/v1/auth/login/totp", new { mfaToken = challenge.MfaToken, code = Code(secret, 2) })).StatusCode);

        // The same code cannot be replayed on a new challenge (its step is now the last used one), and the step
        // after that is outside the ±1 window at this moment. One wrong code does not kill the challenge: a
        // recovery code still completes it.
        var challenge2 = await PasswordStepAsync(anon, email);
        Assert.Equal(HttpStatusCode.Unauthorized, (await anon.PostAsJsonAsync("/v1/auth/login/totp", new { mfaToken = challenge2.MfaToken, code })).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await anon.PostAsJsonAsync("/v1/auth/login/totp", new { mfaToken = challenge2.MfaToken, code = Code(secret, 2) })).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await anon.PostAsJsonAsync("/v1/auth/login/totp", new { mfaToken = challenge2.MfaToken, code = recoveryCodes[0] })).StatusCode);
    }

    [Fact]
    public async Task WrongCodes_GenericGeneric401_FifthKillsChallenge_PasswordStepNeededAgain()
    {
        var (email, _, secret, _) = await EnabledAccountAsync();
        var anon = _factory.CreateClient();
        var challenge = await PasswordStepAsync(anon, email);

        string? firstBody = null;
        for (var i = 0; i < 5; i++)
        {
            var resp = await anon.PostAsJsonAsync("/v1/auth/login/totp", new { mfaToken = challenge.MfaToken, code = "000000" });
            Assert.Equal(HttpStatusCode.Unauthorized, resp.StatusCode);
            using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
            var detail = doc.RootElement.GetProperty("detail").GetString();
            firstBody ??= detail;
            Assert.Equal(firstBody, detail); // no attempts-left hint
        }

        // The right code no longer helps: the challenge is spent.
        Assert.Equal(HttpStatusCode.Unauthorized, (await anon.PostAsJsonAsync("/v1/auth/login/totp", new { mfaToken = challenge.MfaToken, code = Code(secret, 1) })).StatusCode);
        // Malformed token and bogus token: same generic 401.
        Assert.Equal(HttpStatusCode.Unauthorized, (await anon.PostAsJsonAsync("/v1/auth/login/totp", new { mfaToken = "nope", code = Code(secret, 1) })).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await anon.PostAsJsonAsync("/v1/auth/login/totp", new { mfaToken = new string('B', 43), code = Code(secret, 1) })).StatusCode);
        Assert.Equal(1L, await _factory.ActiveSessionCountAsync(email));
    }

    [Fact]
    public async Task ParallelWrongCodes_CannotExceedTheAttemptLimit_TheChallengeDies()
    {
        var (email, _, secret, _) = await EnabledAccountAsync();
        var anon = _factory.CreateClient();
        var challenge = await PasswordStepAsync(anon, email);

        // 30 wrong codes at once: before the fix every request that read the challenge before the fifth failure
        // committed got its code checked. Now an attempt is reserved first, so at most 5 codes are ever checked.
        var wrong = await Task.WhenAll(Enumerable.Range(0, 30).Select(i =>
            _factory.CreateClient().PostAsJsonAsync("/v1/auth/login/totp", new { mfaToken = challenge.MfaToken, code = (100000 + i).ToString() })));
        Assert.All(wrong, r => Assert.Equal(HttpStatusCode.Unauthorized, r.StatusCode));

        Assert.Equal(5L, await _factory.QueryScalarAsync<long>(
            "SELECT MAX(m.attempt_count) FROM mfa_challenges m JOIN accounts a ON a.id=m.account_id WHERE a.normalized_email=@e", "@e", email.ToUpperInvariant()));
        Assert.Equal(HttpStatusCode.Unauthorized, (await anon.PostAsJsonAsync("/v1/auth/login/totp", new { mfaToken = challenge.MfaToken, code = Code(secret, 1) })).StatusCode);
    }

    [Fact]
    public async Task RecoveryCode_SignsIn_Once_AndCountsDown()
    {
        var (email, authed, _, codes) = await EnabledAccountAsync();
        var anon = _factory.CreateClient();

        var c1 = await PasswordStepAsync(anon, email);
        var ok = await anon.PostAsJsonAsync("/v1/auth/login/totp", new { mfaToken = c1.MfaToken, code = codes[0].ToUpperInvariant().Replace("-", " ") });
        Assert.Equal(HttpStatusCode.OK, ok.StatusCode);

        var c2 = await PasswordStepAsync(anon, email);
        Assert.Equal(HttpStatusCode.Unauthorized, (await anon.PostAsJsonAsync("/v1/auth/login/totp", new { mfaToken = c2.MfaToken, code = codes[0] })).StatusCode);

        var status = await (await authed.GetAsync("/v1/account/totp")).Content.ReadFromJsonAsync<TotpStatusResponse>();
        Assert.Equal(9, status!.RecoveryCodesRemaining);
    }

    [Fact]
    public async Task RegenerateRecoveryCodes_ReplacesSet_Disable_ReturnsToPasswordOnlyLogin()
    {
        var (email, authed, secret, codes) = await EnabledAccountAsync();
        var anon = _factory.CreateClient();

        Assert.Equal(HttpStatusCode.Forbidden, (await authed.PostAsJsonAsync("/v1/account/totp/recovery-codes", new { password = "Wrong-Password-Entirely-9", code = Code(secret, 1) })).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await authed.PostAsJsonAsync("/v1/account/totp/recovery-codes", new { password = Password, code = "000000" })).StatusCode);
        var regen = await authed.PostAsJsonAsync("/v1/account/totp/recovery-codes", new { password = Password, code = Code(secret, 1) });
        Assert.Equal(HttpStatusCode.OK, regen.StatusCode);
        var fresh = (await regen.Content.ReadFromJsonAsync<TotpRecoveryCodesResponse>())!.RecoveryCodes;
        Assert.Equal(10, fresh.Count);
        Assert.Empty(fresh.Intersect(codes));

        // Old codes are dead, a new one works.
        var c1 = await PasswordStepAsync(anon, email);
        Assert.Equal(HttpStatusCode.Unauthorized, (await anon.PostAsJsonAsync("/v1/auth/login/totp", new { mfaToken = c1.MfaToken, code = codes[1] })).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await anon.PostAsJsonAsync("/v1/auth/login/totp", new { mfaToken = c1.MfaToken, code = fresh[0] })).StatusCode);

        // Disable: wrong password/code → 403 and still enabled; right → 204 and password-only login again.
        Assert.Equal(HttpStatusCode.Forbidden, (await authed.PostAsJsonAsync("/v1/account/totp/disable", new { password = Password, code = "000000" })).StatusCode);
        Assert.True((await (await authed.GetAsync("/v1/account/totp")).Content.ReadFromJsonAsync<TotpStatusResponse>())!.Enabled);
        Assert.Equal(HttpStatusCode.NoContent, (await authed.PostAsJsonAsync("/v1/account/totp/disable", new { password = Password, code = fresh[1] })).StatusCode);
        Assert.Equal(new TotpStatusResponse(false, null, 0, false), await (await authed.GetAsync("/v1/account/totp")).Content.ReadFromJsonAsync<TotpStatusResponse>());
        Assert.Equal(HttpStatusCode.Conflict, (await authed.PostAsJsonAsync("/v1/account/totp/disable", new { password = Password, code = fresh[2] })).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await anon.PostAsJsonAsync("/v1/auth/login", new { email, password = Password })).StatusCode);
    }

    [Fact]
    public async Task PasswordResetBetweenSteps_KillsTheChallenge()
    {
        var (email, _, secret, _) = await EnabledAccountAsync();
        var anon = _factory.CreateClient();
        var challenge = await PasswordStepAsync(anon, email);

        // Reset the password via the phase-6 flow while the challenge is open.
        (await anon.PostAsJsonAsync("/v1/auth/forgot-password", new { email })).EnsureSuccessStatusCode();
        using (var scope = Microsoft.Extensions.DependencyInjection.ServiceProviderServiceExtensions.CreateScope(_factory.Services))
        {
            await Microsoft.Extensions.DependencyInjection.ServiceProviderServiceExtensions.GetRequiredService<BitosX.Infrastructure.Email.IEmailOutboxDispatcher>(scope.ServiceProvider).ProcessDueOnceAsync();
        }
        var token = CapturingEmailSender.ExtractToken(_factory.Emails.Sent[^1]);
        (await anon.PostAsJsonAsync("/v1/auth/reset-password", new { token, password = "Another-Strong-Password-22" })).EnsureSuccessStatusCode();

        Assert.Equal(HttpStatusCode.Unauthorized, (await anon.PostAsJsonAsync("/v1/auth/login/totp", new { mfaToken = challenge.MfaToken, code = Code(secret, 1) })).StatusCode);
        // TOTP stays on after a reset: the new password still needs the second step.
        var resp = await anon.PostAsJsonAsync("/v1/auth/login", new { email, password = "Another-Strong-Password-22" });
        Assert.Equal(HttpStatusCode.Accepted, resp.StatusCode);
    }

    [Fact]
    public async Task Unauthenticated_TotpManagement_Is401_AndBodiesAreCapped()
    {
        var anon = _factory.CreateClient();
        Assert.Equal(HttpStatusCode.Unauthorized, (await anon.GetAsync("/v1/account/totp")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await anon.PostAsJsonAsync("/v1/account/totp/enroll", new { password = Password })).StatusCode);

        using var big = new HttpRequestMessage(HttpMethod.Post, "/v1/auth/login/totp") { Content = JsonContent.Create(new { mfaToken = new string('A', 43), code = "123456", padding = new string('x', 5000) }) };
        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, (await anon.SendAsync(big)).StatusCode);
    }
}

/// <summary>Totp capability off: TOTP routes answer 503, and an account that already has TOTP is refused at login (never bypassed).</summary>
public sealed class TotpCapabilityOffTests
{
    private const string Password = "Correct-Horse-Battery-Staple-1";

    [Fact]
    public async Task WithoutTotpKey_RoutesAre503_AndEnrolledAccountCannotSignIn()
    {
        // Enroll with the capability on, then boot the API against the same DB without the key.
        string email;
        await using (var on = new LoginApiFactory())
        {
            await on.ResetDatabaseAsync();
            var client = on.CreateClient();
            email = await on.CreateVerifiedAccountAsync(client, Password);
            var login = await LoginApiFactory.LoginAsync(client, email, Password);
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", login.AccessToken);
            var enrolled = (await (await client.PostAsJsonAsync("/v1/account/totp/enroll", new { password = Password })).Content.ReadFromJsonAsync<TotpEnrollResponse>())!;
            Base32.TryDecode(enrolled.Secret, out var secret);
            var code = Rfc6238Totp.Compute(secret, Rfc6238Totp.Step(DateTimeOffset.UtcNow.ToUnixTimeSeconds(), 30), 6);
            (await client.PostAsJsonAsync("/v1/account/totp/confirm", new { code })).EnsureSuccessStatusCode();
        }

        await using var off = new LoginApiFactory { TotpCapability = false };
        var anon = off.CreateClient();
        var resp = await anon.PostAsJsonAsync("/v1/auth/login", new { email, password = Password });
        Assert.Equal(HttpStatusCode.ServiceUnavailable, resp.StatusCode); // fail closed: no password-only session
        Assert.Equal(HttpStatusCode.ServiceUnavailable, (await anon.PostAsJsonAsync("/v1/auth/login/totp", new { mfaToken = new string('A', 43), code = "123456" })).StatusCode);
        Assert.Equal(1L, await off.QueryScalarAsync<long>("SELECT COUNT(*) FROM sessions s JOIN accounts a ON a.id=s.account_id WHERE a.normalized_email=@e AND s.revoked_at IS NULL", "@e", email.ToUpperInvariant()));

        // An account without TOTP still signs in and sees the TOTP routes as unavailable.
        var plain = await off.CreateVerifiedAccountAsync(anon, Password);
        var tokens = await LoginApiFactory.LoginAsync(anon, plain, Password);
        anon.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tokens.AccessToken);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, (await anon.GetAsync("/v1/account/totp")).StatusCode);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, (await anon.PostAsJsonAsync("/v1/account/totp/enroll", new { password = Password })).StatusCode);
    }
}
