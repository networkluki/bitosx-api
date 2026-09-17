namespace BitosX.Application.Security;

/// <summary>
/// Refresh-token configuration. The <see cref="Pepper"/> is an independent server secret
/// (distinct from the JWT signing key, the email-verification pepper, and the outbox key),
/// held only in the secret store. It is a Base64 string that must decode to ≥ 32 bytes and
/// is used as the HMAC-SHA256 key over the raw 32 token bytes. The pepper is stable and is
/// never silently rotated (rotation is a future explicit overlap operation).
/// </summary>
public sealed class RefreshTokenOptions
{
    /// <summary>HMAC pepper (Security:RefreshTokenPepper), Base64, ≥ 32 decoded bytes. Required.</summary>
    public string Pepper { get; set; } = string.Empty;

    /// <summary>Idle session lifetime; policy default 30 days.</summary>
    public TimeSpan IdleLifetime { get; set; } = TimeSpan.FromDays(30);

    /// <summary>Absolute session lifetime; policy default 90 days.</summary>
    public TimeSpan AbsoluteLifetime { get; set; } = TimeSpan.FromDays(90);

    /// <summary>Non-revoking duplicate-refresh window; policy default 5 seconds.</summary>
    public TimeSpan ReuseGraceWindow { get; set; } = TimeSpan.FromSeconds(5);
}
