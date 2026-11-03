using System.Collections.Concurrent;
using BitosX.Application.Passkeys;

namespace BitosX.Api.Tests;

/// <summary>Records passkey security events so tests can prove WHY a request was refused (the client only sees a generic answer).</summary>
internal sealed class RecordingPasskeyLog : IPasskeySecurityLog
{
    public ConcurrentQueue<string> Events { get; } = new();

    public string? LastRefusal => Events.LastOrDefault(e => e.StartsWith("refused:", StringComparison.Ordinal));

    public void Clear() => Events.Clear();

    public void Registered(Guid accountId, Guid passkeyId, bool backupEligible) => Events.Enqueue($"registered:{passkeyId}");

    public void Renamed(Guid accountId, Guid passkeyId) => Events.Enqueue($"renamed:{passkeyId}");

    public void Deleted(Guid accountId, Guid passkeyId) => Events.Enqueue($"deleted:{passkeyId}");

    public void Used(Guid accountId, Guid passkeyId, bool passwordless) => Events.Enqueue($"used:{(passwordless ? "passwordless" : "mfa")}:{passkeyId}");

    public void Refused(string ceremony, string reason, Guid? accountId, Guid? passkeyId) => Events.Enqueue($"refused:{ceremony}:{reason}");
}
