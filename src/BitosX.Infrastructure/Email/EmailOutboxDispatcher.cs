using BitosX.Application.Abstractions.Persistence;
using BitosX.Application.Email;
using BitosX.Application.Verification;
using Microsoft.Extensions.Logging;

namespace BitosX.Infrastructure.Email;

/// <summary>Drains the email outbox once (used by the hosted background service and tests).</summary>
public interface IEmailOutboxDispatcher
{
    Task ProcessDueOnceAsync(CancellationToken cancellationToken = default);
    Task RunCleanupOnceAsync(CancellationToken cancellationToken = default);
}

/// <summary>
/// Processes due outbox rows: leases them, and BEFORE decrypting/sending checks
/// the linked challenge is still active (present, not consumed, not invalidated,
/// not expired). Verifies recipient integrity (AEAD AAD + decrypted toAddress ==
/// row recipient) before sending. Never sends for a stale/expired challenge;
/// never extends the token TTL; erases payloads on terminal state; never logs the
/// token, decrypted payload, or SMTP credentials.
/// </summary>
public sealed class EmailOutboxDispatcher : IEmailOutboxDispatcher
{
    private readonly IEmailOutboxStore _store;
    private readonly IOutboxPayloadProtector _protector;
    private readonly IEmailSender _sender;
    private readonly IVerificationEmailComposer _composer;
    private readonly EmailOutboxOptions _options;
    private readonly EmailVerificationSecurityOptions _verification;
    private readonly TimeProvider _clock;
    private readonly ILogger<EmailOutboxDispatcher> _logger;
    private readonly string _workerId = $"outbox-{Guid.NewGuid():N}";

    public EmailOutboxDispatcher(
        IEmailOutboxStore store,
        IOutboxPayloadProtector protector,
        IEmailSender sender,
        IVerificationEmailComposer composer,
        EmailOutboxOptions options,
        EmailVerificationSecurityOptions verification,
        TimeProvider clock,
        ILogger<EmailOutboxDispatcher> logger)
    {
        _store = store;
        _protector = protector;
        _sender = sender;
        _composer = composer;
        _options = options;
        _verification = verification;
        _clock = clock;
        _logger = logger;
    }

    public async Task ProcessDueOnceAsync(CancellationToken cancellationToken = default)
    {
        var now = _clock.GetUtcNow().UtcDateTime;
        var leaseUntil = now + _options.LeaseDuration;
        var rows = await _store.ClaimDueAsync(now, leaseUntil, _workerId, _options.BatchSize, cancellationToken).ConfigureAwait(false);

        foreach (var row in rows)
        {
            cancellationToken.ThrowIfCancellationRequested();
            await ProcessRowAsync(row, now, cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task ProcessRowAsync(OutboxDueRow row, DateTime now, CancellationToken cancellationToken)
    {
        // (1) Eligibility BEFORE decrypt/send: challenge must still be active.
        var challengeActive = row.ChallengeConsumedAt is null
            && row.ChallengeInvalidatedAt is null
            && row.ChallengeExpiresAt > now;
        if (!challengeActive)
        {
            await _store.MarkFailedAndErasePayloadAsync(row.Id, now, cancellationToken).ConfigureAwait(false);
            return; // never send a stale/expired/consumed/invalidated verification link
        }

        // (2) Recipient integrity: AEAD AAD binds the recipient; decrypt authenticates it.
        var aad = new OutboxAad(row.Id, row.Payload.Version, row.MessageType, row.RecipientEmail);
        if (!_protector.TryUnprotect(row.Payload, aad, out var payload) || payload is null)
        {
            _logger.LogWarning("Outbox message {OutboxId} failed payload integrity check; not sending.", row.Id);
            await _store.MarkFailedAndErasePayloadAsync(row.Id, now, cancellationToken).ConfigureAwait(false);
            return;
        }

        // (3) Defense-in-depth: decrypted recipient must equal the authenticated row recipient.
        if (!string.Equals(payload.ToAddress, row.RecipientEmail, StringComparison.Ordinal))
        {
            _logger.LogWarning("Outbox message {OutboxId} recipient mismatch; not sending.", row.Id);
            await _store.MarkFailedAndErasePayloadAsync(row.Id, now, cancellationToken).ConfigureAwait(false);
            return;
        }

        // (4) Compose + send.
        var expiresInMinutes = Math.Max(1, (int)Math.Ceiling((payload.ExpiresAtUtc - now).TotalMinutes));
        var email = _composer.Compose(row.RecipientEmail, payload.TokenBase64Url, payload.ExpiresAtUtc, expiresInMinutes);
        var result = await _sender.SendAsync(email, cancellationToken).ConfigureAwait(false);

        if (result == EmailSendResult.Sent)
        {
            await _store.MarkSentAndErasePayloadAsync(row.Id, now, cancellationToken).ConfigureAwait(false);
            return;
        }

        // (5) Transient failure: retry with backoff only if the next attempt is still
        // within the token lifetime; otherwise fail terminally (never extend the TTL).
        var nextAttempt = row.AttemptCount + 1;
        var delay = TimeSpan.FromSeconds(_options.BackoffBase.TotalSeconds * Math.Pow(2, row.AttemptCount));
        var nextAvailable = now + delay;
        if (nextAttempt >= _options.MaxAttempts || nextAvailable >= row.ChallengeExpiresAt)
        {
            await _store.MarkFailedAndErasePayloadAsync(row.Id, now, cancellationToken).ConfigureAwait(false);
        }
        else
        {
            await _store.RescheduleAsync(row.Id, nextAvailable, now, cancellationToken).ConfigureAwait(false);
        }
    }

    public async Task RunCleanupOnceAsync(CancellationToken cancellationToken = default)
    {
        var now = _clock.GetUtcNow().UtcDateTime;
        await _store.FailAndEraseIneligibleAsync(now, cancellationToken).ConfigureAwait(false);
        await _store.DeleteSanitizedOlderThanAsync(now - _options.RetentionPeriod, cancellationToken).ConfigureAwait(false);
    }
}
