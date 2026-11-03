using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using BitosX.Application.Mfa;
using BitosX.Contracts.Accounts;
using BitosX.Infrastructure.Email;
using Microsoft.Extensions.DependencyInjection;

namespace BitosX.Api.Tests;

/// <summary>
/// <c>POST /v1/account/password</c> end to end: the current password (and the code when TOTP is on) confirms
/// it, every other session dies, the caller's survives, open reset links die, and every failure is the generic
/// 403 that leaves the session valid. Also covers the second factor on <c>POST /v1/account/delete</c>.
/// </summary>
public sealed class ChangePasswordEndpointTests : IClassFixture<LoginApiFactory>, IAsyncLifetime
{
    private const string Password = "Correct-Horse-Battery-Staple-1";
    private const string NewPassword = "Brand-New-Account-Password-2";

    private readonly LoginApiFactory _factory;

    public ChangePasswordEndpointTests(LoginApiFactory factory) => _factory = factory;

    public async Task InitializeAsync() => await _factory.ResetDatabaseAsync();
    public Task DisposeAsync() => Task.CompletedTask;

    private HttpClient Authed(string accessToken, LoginApiFactory? factory = null)
    {
        var client = (factory ?? _factory).CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        return client;
    }

    private static string Code(byte[] secret)
        => Rfc6238Totp.Compute(secret, Rfc6238Totp.Step(DateTimeOffset.UtcNow.ToUnixTimeSeconds(), 30), 6);

    private async Task<(byte[] Secret, IReadOnlyList<string> RecoveryCodes)> EnableTotpAsync(HttpClient authed)
    {
        var enrolled = (await (await authed.PostAsJsonAsync("/v1/account/totp/enroll", new { password = Password })).Content.ReadFromJsonAsync<TotpEnrollResponse>())!;
        Assert.True(Base32.TryDecode(enrolled.Secret, out var secret));
        var confirm = await authed.PostAsJsonAsync("/v1/account/totp/confirm", new { code = Code(secret) });
        Assert.Equal(HttpStatusCode.OK, confirm.StatusCode);
        return (secret, (await confirm.Content.ReadFromJsonAsync<TotpRecoveryCodesResponse>())!.RecoveryCodes);
    }

    [Fact]
    public async Task Change_Returns204_KeepsTheCaller_RevokesOthers_NewPasswordSignsIn()
    {
        var anon = _factory.CreateClient();
        var email = await _factory.CreateVerifiedAccountAsync(anon, Password);
        var caller = await LoginApiFactory.LoginAsync(anon, email, Password);
        var other = await LoginApiFactory.LoginAsync(anon, email, Password);
        var authed = Authed(caller.AccessToken);

        var resp = await authed.PostAsJsonAsync("/v1/account/password", new { currentPassword = Password, newPassword = NewPassword });

        Assert.Equal(HttpStatusCode.NoContent, resp.StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await authed.GetAsync("/v1/account/me")).StatusCode);                        // caller stays signed in
        Assert.Equal(HttpStatusCode.Unauthorized, (await Authed(other.AccessToken).GetAsync("/v1/account/me")).StatusCode); // others are out
        Assert.Equal(HttpStatusCode.Unauthorized, (await anon.PostAsJsonAsync("/v1/auth/refresh", new { refreshToken = other.RefreshToken })).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await anon.PostAsJsonAsync("/v1/auth/refresh", new { refreshToken = caller.RefreshToken })).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await anon.PostAsJsonAsync("/v1/auth/login", new { email, password = Password })).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await anon.PostAsJsonAsync("/v1/auth/login", new { email, password = NewPassword })).StatusCode);
    }

    [Fact]
    public async Task Change_InvalidatesAnOpenResetLink()
    {
        var anon = _factory.CreateClient();
        var email = await _factory.CreateVerifiedAccountAsync(anon, Password);
        var caller = await LoginApiFactory.LoginAsync(anon, email, Password);
        Assert.Equal(HttpStatusCode.Accepted, (await anon.PostAsJsonAsync("/v1/auth/forgot-password", new { email })).StatusCode);
        using (var scope = _factory.Services.CreateScope())
        {
            await scope.ServiceProvider.GetRequiredService<IEmailOutboxDispatcher>().ProcessDueOnceAsync();
        }

        var resetToken = CapturingEmailSender.ExtractToken(_factory.Emails.Sent[^1]);

        Assert.Equal(HttpStatusCode.NoContent, (await Authed(caller.AccessToken).PostAsJsonAsync("/v1/account/password", new { currentPassword = Password, newPassword = NewPassword })).StatusCode);

        var reset = await anon.PostAsJsonAsync("/v1/auth/reset-password", new { token = resetToken, password = "Attacker-Chosen-Password-3" });
        Assert.Equal(HttpStatusCode.BadRequest, reset.StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await anon.PostAsJsonAsync("/v1/auth/login", new { email, password = NewPassword })).StatusCode);
    }

    [Fact]
    public async Task WrongCurrentPassword_Returns403_SessionStaysValid_NothingChanged()
    {
        var anon = _factory.CreateClient();
        var email = await _factory.CreateVerifiedAccountAsync(anon, Password);
        var caller = await LoginApiFactory.LoginAsync(anon, email, Password);
        var other = await LoginApiFactory.LoginAsync(anon, email, Password);
        var authed = Authed(caller.AccessToken);

        var resp = await authed.PostAsJsonAsync("/v1/account/password", new { currentPassword = "Wrong-Password-Entirely-9", newPassword = NewPassword });

        Assert.Equal(HttpStatusCode.Forbidden, resp.StatusCode);
        Assert.Contains("application/problem+json", resp.Content.Headers.ContentType?.MediaType);
        Assert.Contains("Password confirmation failed.", await resp.Content.ReadAsStringAsync());
        Assert.Equal(HttpStatusCode.OK, (await authed.GetAsync("/v1/account/me")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await Authed(other.AccessToken).GetAsync("/v1/account/me")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await anon.PostAsJsonAsync("/v1/auth/login", new { email, password = Password })).StatusCode);
    }

    [Theory]
    [InlineData("short")]
    [InlineData("")]
    public async Task NewPasswordOutsidePolicy_Returns400_WithThePolicyInTheDetail(string newPassword)
    {
        var anon = _factory.CreateClient();
        var email = await _factory.CreateVerifiedAccountAsync(anon, Password);
        var authed = Authed((await LoginApiFactory.LoginAsync(anon, email, Password)).AccessToken);

        var resp = await authed.PostAsJsonAsync("/v1/account/password", new { currentPassword = Password, newPassword });

        Assert.Equal(HttpStatusCode.BadRequest, resp.StatusCode);
        Assert.Contains("between 12 and 128 characters", await resp.Content.ReadAsStringAsync());
        Assert.Equal(HttpStatusCode.OK, (await anon.PostAsJsonAsync("/v1/auth/login", new { email, password = Password })).StatusCode);
    }

    [Fact]
    public async Task Unauthenticated_Returns401_AndOversizedBody_Returns413()
    {
        var anon = _factory.CreateClient();
        Assert.Equal(HttpStatusCode.Unauthorized, (await anon.PostAsJsonAsync("/v1/account/password", new { currentPassword = Password, newPassword = NewPassword })).StatusCode);

        var email = await _factory.CreateVerifiedAccountAsync(anon, Password);
        var authed = Authed((await LoginApiFactory.LoginAsync(anon, email, Password)).AccessToken);
        using var request = new HttpRequestMessage(HttpMethod.Post, "/v1/account/password")
        {
            Content = JsonContent.Create(new { currentPassword = Password, newPassword = NewPassword, padding = new string('x', 5000) }),
        };
        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, (await authed.SendAsync(request)).StatusCode);
    }

    [Fact]
    public async Task WithTotp_CodeIsRequired_TotpOrRecoveryCodeWorks()
    {
        var anon = _factory.CreateClient();
        var email = await _factory.CreateVerifiedAccountAsync(anon, Password);
        var authed = Authed((await LoginApiFactory.LoginAsync(anon, email, Password)).AccessToken);
        var (_, recoveryCodes) = await EnableTotpAsync(authed);

        Assert.Equal(HttpStatusCode.Forbidden, (await authed.PostAsJsonAsync("/v1/account/password", new { currentPassword = Password, newPassword = NewPassword })).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await authed.PostAsJsonAsync("/v1/account/password", new { currentPassword = Password, newPassword = NewPassword, code = "000000" })).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await authed.GetAsync("/v1/account/me")).StatusCode);

        var ok = await authed.PostAsJsonAsync("/v1/account/password", new { currentPassword = Password, newPassword = NewPassword, code = recoveryCodes[0] });
        Assert.Equal(HttpStatusCode.NoContent, ok.StatusCode);

        // The recovery code is single use.
        var again = await authed.PostAsJsonAsync("/v1/account/password", new { currentPassword = NewPassword, newPassword = Password, code = recoveryCodes[0] });
        Assert.Equal(HttpStatusCode.Forbidden, again.StatusCode);
    }

    [Fact]
    public async Task DeleteAccount_WithTotp_RequiresTheCode()
    {
        var anon = _factory.CreateClient();
        var email = await _factory.CreateVerifiedAccountAsync(anon, Password);
        var authed = Authed((await LoginApiFactory.LoginAsync(anon, email, Password)).AccessToken);
        var (secret, _) = await EnableTotpAsync(authed);

        Assert.Equal(HttpStatusCode.Forbidden, (await authed.PostAsJsonAsync("/v1/account/delete", new { password = Password })).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await authed.PostAsJsonAsync("/v1/account/delete", new { password = Password, code = "000000" })).StatusCode);
        Assert.Equal(1L, await _factory.QueryScalarAsync<long>("SELECT COUNT(*) FROM accounts WHERE normalized_email=@e", "@e", email.ToUpperInvariant()));

        // A TOTP code for the next step (inside the ±1 window, above the step the confirm used).
        var next = Rfc6238Totp.Compute(secret, Rfc6238Totp.Step(DateTimeOffset.UtcNow.ToUnixTimeSeconds(), 30) + 1, 6);
        Assert.Equal(HttpStatusCode.NoContent, (await authed.PostAsJsonAsync("/v1/account/delete", new { password = Password, code = next })).StatusCode);
        Assert.Equal(0L, await _factory.QueryScalarAsync<long>("SELECT COUNT(*) FROM accounts WHERE normalized_email=@e", "@e", email.ToUpperInvariant()));
    }

    [Fact]
    public async Task TotpConfirmed_ButCapabilityOff_DeleteAndChange_Return503_NothingChanges()
    {
        await using var off = new LoginApiFactory { TotpCapability = false };
        var anon = off.CreateClient();
        var email = await off.CreateVerifiedAccountAsync(anon, Password);
        var authed = Authed((await LoginApiFactory.LoginAsync(anon, email, Password)).AccessToken, off);
        var accountId = await off.QueryScalarAsync<Guid>("SELECT id FROM accounts WHERE normalized_email=@e", "@e", email.ToUpperInvariant());
        await off.ExecuteAsync(
            """
            INSERT INTO account_totp (account_id, secret_version, secret_nonce, secret_ciphertext, secret_tag, created_at, confirmed_at, last_used_step)
            VALUES (@a, 1, RANDOM_BYTES(12), RANDOM_BYTES(20), RANDOM_BYTES(16), UTC_TIMESTAMP(6), UTC_TIMESTAMP(6), NULL);
            """, "@a", accountId);

        var delete = await authed.PostAsJsonAsync("/v1/account/delete", new { password = Password, code = "123456" });
        Assert.Equal(HttpStatusCode.ServiceUnavailable, delete.StatusCode);
        var change = await authed.PostAsJsonAsync("/v1/account/password", new { currentPassword = Password, newPassword = NewPassword, code = "123456" });
        Assert.Equal(HttpStatusCode.ServiceUnavailable, change.StatusCode);

        Assert.Equal(1L, await off.QueryScalarAsync<long>("SELECT COUNT(*) FROM accounts WHERE id=@a", "@a", accountId));
        Assert.Equal(HttpStatusCode.OK, (await authed.GetAsync("/v1/account/me")).StatusCode);
    }
}
