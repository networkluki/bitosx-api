using BitosX.Application.Passkeys;
using Microsoft.Extensions.Logging;

namespace BitosX.Infrastructure.Passkeys;

/// <summary>
/// Passkey security events as structured log lines: account and passkey ids (server-side GUIDs) and fixed reason
/// codes only — never a credential id, key, challenge, user handle, email address or anything the client sent.
/// </summary>
public sealed class LoggerPasskeySecurityLog : IPasskeySecurityLog
{
    private readonly ILogger<LoggerPasskeySecurityLog> _logger;

    public LoggerPasskeySecurityLog(ILogger<LoggerPasskeySecurityLog> logger) => _logger = logger;

    public void Registered(Guid accountId, Guid passkeyId, bool backupEligible)
        => _logger.LogInformation("Passkey registered: account {AccountId} passkey {PasskeyId} (backup eligible: {BackupEligible}).", accountId, passkeyId, backupEligible);

    public void Renamed(Guid accountId, Guid passkeyId)
        => _logger.LogInformation("Passkey renamed: account {AccountId} passkey {PasskeyId}.", accountId, passkeyId);

    public void Deleted(Guid accountId, Guid passkeyId)
        => _logger.LogInformation("Passkey deleted: account {AccountId} passkey {PasskeyId}.", accountId, passkeyId);

    public void Used(Guid accountId, Guid passkeyId, bool passwordless)
        => _logger.LogInformation("Passkey sign-in ({Mode}): account {AccountId} passkey {PasskeyId}.", passwordless ? "passwordless" : "second factor", accountId, passkeyId);

    public void Refused(string ceremony, string reason, Guid? accountId, Guid? passkeyId)
    {
        if (reason is "counter-regression" or "counter-race")
        {
            _logger.LogWarning(
                "Passkey {Ceremony} refused: {Reason} (the signature counter did not increase; possible cloned authenticator) account {AccountId} passkey {PasskeyId}.",
                ceremony, reason, accountId, passkeyId);
            return;
        }

        _logger.LogWarning("Passkey {Ceremony} refused: {Reason} account {AccountId} passkey {PasskeyId}.", ceremony, reason, accountId, passkeyId);
    }
}
