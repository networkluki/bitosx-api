using System.Security.Cryptography;
using System.Text;
using BitosX.Application.Abstractions.Persistence;
using BitosX.Application.Accounts;
using BitosX.Application.Email;
using BitosX.Application.Security;
using BitosX.Application.Verification;

namespace BitosX.Application.Tests;

internal sealed class FakeAccountRepository : IAccountRepository
{
    private readonly Dictionary<string, Account> _byNormalized = new(StringComparer.Ordinal);
    private readonly Dictionary<Guid, Account> _byId = [];

    public void Seed(Account a) { _byNormalized[a.NormalizedEmail] = a; _byId[a.Id] = a; }

    public Task AddAsync(Account account, CancellationToken ct = default) { Seed(account); return Task.CompletedTask; }
    public Task<Account?> GetByIdAsync(Guid id, CancellationToken ct = default) => Task.FromResult(_byId.GetValueOrDefault(id));
    public Task<Account?> GetByNormalizedEmailAsync(string n, CancellationToken ct = default) => Task.FromResult(_byNormalized.GetValueOrDefault(n));
}

internal sealed class FakeRegistrationStore : IAccountRegistrationStore
{
    public int Calls { get; private set; }
    public Account? LastAccount { get; private set; }
    public RegistrationOutcome Outcome { get; set; } = RegistrationOutcome.Created;

    public Task<RegistrationOutcome> CreateUnverifiedAccountWithChallengeAndOutboxAsync(
        Account account, EmailVerificationChallenge challenge, EmailOutboxMessage outbox, CancellationToken ct = default)
    {
        Calls++;
        LastAccount = account;
        return Task.FromResult(Outcome);
    }
}

internal sealed class FakeVerificationStore : IEmailVerificationStore
{
    public ActiveChallengeView? ActiveToReturn { get; set; }
    public VerificationOutcome FinalizeOutcome { get; set; } = VerificationOutcome.Verified;
    public ResendOutcome ReplaceOutcome { get; set; } = ResendOutcome.Replaced;
    public int FinalizeCalls { get; private set; }
    public int ReplaceCalls { get; private set; }

    public Task<ActiveChallengeView?> FindActiveChallengeByVerifierAsync(byte[] v, DateTime now, CancellationToken ct = default)
        => Task.FromResult(ActiveToReturn);

    public Task<VerificationOutcome> FinalizeVerificationAsync(byte[] v, string phc, CancellationToken ct = default)
    { FinalizeCalls++; return Task.FromResult(FinalizeOutcome); }

    public Task<ResendOutcome> ReplaceActiveChallengeAsync(Guid a, EmailVerificationChallenge c, EmailOutboxMessage o, DateTime now, TimeSpan min, CancellationToken ct = default)
    { ReplaceCalls++; return Task.FromResult(ReplaceOutcome); }
}

/// <summary>Counts hashing calls to prove Argon2 is (not) invoked.</summary>
internal sealed class SpyPasswordHasher : IAccountPasswordHasher
{
    public int HashCalls { get; private set; }
    public string Hash(string password) { HashCalls++; return "$argon2id$v=19$m=8192,t=1,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYQ"; }
    public PasswordVerificationResult Verify(string password, string encoded) => PasswordVerificationResult.Success;
}

internal sealed class FakeTokenFactory : IEmailVerificationTokenFactory
{
    public GeneratedToken GenerateToken()
    {
        var t = RandomNumberGenerator.GetBytes(32);
        return new GeneratedToken(Convert.ToHexString(t), SHA256.HashData(t));
    }

    public byte[] ComputeVerifier(string tokenBase64Url)
    {
        if (tokenBase64Url.Contains('!')) throw new FormatException("bad token");
        return SHA256.HashData(Encoding.UTF8.GetBytes(tokenBase64Url));
    }
}

internal sealed class FakeOutboxPayloadProtector : IOutboxPayloadProtector
{
    public ProtectedOutboxPayload Protect(OutboxPayload p, OutboxAad aad)
        => new(1, new byte[12], Encoding.UTF8.GetBytes(p.TokenBase64Url), new byte[16]);

    public bool TryUnprotect(ProtectedOutboxPayload p, OutboxAad aad, out OutboxPayload? payload)
    { payload = null; return false; }
}
