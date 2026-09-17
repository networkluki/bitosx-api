namespace BitosX.Application.Security;

/// <summary>
/// Non-secret refresh/session policy settings. The refresh-token verifier is
/// <c>SHA-256(raw 32 token bytes)</c> — a fixed part of the protocol/storage design — so this
/// type holds NO secret and NO SHA-256 configuration. There is deliberately no reuse grace
/// window: any presentation of an already consumed/revoked token is treated as reuse
/// (session-scoped revocation), and clients must single-flight refresh requests.
/// </summary>
public sealed class RefreshTokenOptions
{
    /// <summary>Idle session lifetime; policy default 30 days.</summary>
    public TimeSpan IdleLifetime { get; set; } = TimeSpan.FromDays(30);

    /// <summary>Absolute session lifetime; policy default 90 days.</summary>
    public TimeSpan AbsoluteLifetime { get; set; } = TimeSpan.FromDays(90);
}
