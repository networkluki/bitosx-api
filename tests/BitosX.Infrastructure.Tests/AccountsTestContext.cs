using System.Security.Cryptography;
using BitosX.Application.Abstractions.Persistence;
using BitosX.Application.Accounts;
using Microsoft.Extensions.Time.Testing;
using BitosX.Application.Email;
using BitosX.Application.Verification;
using BitosX.Infrastructure.Email;
using BitosX.Infrastructure.Persistence;
using BitosX.Infrastructure.Security;

namespace BitosX.Infrastructure.Tests;

/// <summary>Wires real registration/verification/outbox components against the test DB.</summary>
internal sealed class AccountsTestContext
{
    public HmacEmailVerificationTokenFactory Tokens { get; }
    public AesGcmOutboxPayloadProtector Protector { get; }
    public Argon2idPasswordHasher Hasher { get; }
    public AccountRegistrationStore RegistrationStore { get; }
    public EmailVerificationStore VerificationStore { get; }
    public EmailOutboxStore OutboxStore { get; }

    /// <summary>Clock owned by the verification store; tests set it to control authoritative finalize time.</summary>
    public FakeTimeProvider Clock { get; } = new(new DateTimeOffset(2026, 9, 16, 12, 0, 0, TimeSpan.Zero));

    public AccountsTestContext(BitosxConnectionFactory factory)
    {
        Tokens = new HmacEmailVerificationTokenFactory(new EmailVerificationSecurityOptions
        {
            Pepper = "test-pepper-" + Convert.ToBase64String(RandomNumberGenerator.GetBytes(24)),
        });
        Protector = new AesGcmOutboxPayloadProtector(new EmailOutboxCryptoOptions
        {
            Key = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),
        });
        // Small Argon2 params keep store tests fast.
        Hasher = new Argon2idPasswordHasher(
            new Application.Security.Argon2ParametersOptions { MemoryKiB = 8192, Iterations = 1, Lanes = 1, MaxConcurrency = 2 },
            new KonsciousArgon2Core());
        RegistrationStore = new AccountRegistrationStore(factory);
        VerificationStore = new EmailVerificationStore(factory, Clock);
        OutboxStore = new EmailOutboxStore(factory);
    }

    public sealed record Registered(Guid AccountId, Guid ChallengeId, Guid OutboxId, string Email, string Token, byte[] Verifier);

    /// <summary>Registers a fresh unverified account (+challenge+outbox) and returns handles.</summary>
    public async Task<Registered> RegisterAsync(DateTime nowUtc, TimeSpan? ttl = null)
    {
        var email = $"user-{Guid.NewGuid():N}@example.com";
        var normalized = EmailNormalizer.Normalize(email);
        var accountId = Guid.NewGuid();
        var challengeId = Guid.NewGuid();
        var outboxId = Guid.NewGuid();
        var expiresAt = nowUtc + (ttl ?? TimeSpan.FromMinutes(30));

        var token = Tokens.GenerateToken();

        var account = new Account
        {
            Id = accountId, Email = email, NormalizedEmail = normalized,
            CreatedAt = nowUtc, UpdatedAt = nowUtc,
        };
        var challenge = new EmailVerificationChallenge
        {
            Id = challengeId, AccountId = accountId, TokenHash = token.VerifierHash,
            CreatedAt = nowUtc, ExpiresAt = expiresAt,
        };
        var payload = Protector.Protect(
            new OutboxPayload(1, accountId, token.TokenBase64Url, expiresAt, email),
            new OutboxAad(outboxId, 1, OutboxMessageTypes.EmailVerification, email));
        var outbox = new EmailOutboxMessage(outboxId, challengeId, OutboxMessageTypes.EmailVerification, email, payload, nowUtc, nowUtc);

        var outcome = await RegistrationStore.CreateUnverifiedAccountWithChallengeAndOutboxAsync(account, challenge, outbox);
        if (outcome != RegistrationOutcome.Created)
        {
            throw new InvalidOperationException($"unexpected registration outcome: {outcome}");
        }

        return new Registered(accountId, challengeId, outboxId, email, token.TokenBase64Url, token.VerifierHash);
    }

    public static DateTime NowMicro()
    {
        var n = DateTime.UtcNow;
        return new DateTime(n.Ticks - (n.Ticks % 10), DateTimeKind.Utc);
    }
}
