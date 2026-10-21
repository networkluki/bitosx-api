namespace BitosX.Application.Sync;

/// <summary>
/// Limits for encrypted-envelope sync (<c>Security:Sync</c>). Validated fail-closed at startup.
/// </summary>
public sealed class VaultSyncOptions
{
    public const string SectionName = "Security:Sync";

    /// <summary>The desktop vault file is capped at 16 MiB (format v1); the server accepts the same.</summary>
    public const int DefaultMaxEnvelopeBytes = 16 * 1024 * 1024;

    /// <summary>The largest envelope accepted, in bytes (decoded). Between 1 KiB and 16 MiB.</summary>
    public int MaxEnvelopeBytes { get; set; } = DefaultMaxEnvelopeBytes;

    /// <summary>
    /// The largest request body the upload endpoint reads: the Base64 of the largest envelope plus the
    /// JSON around it. Derived, never configured.
    /// </summary>
    public long MaxUploadBodyBytes => ((long)MaxEnvelopeBytes + 2) / 3 * 4 + 1024;

    public void Validate()
    {
        if (MaxEnvelopeBytes < 1024 || MaxEnvelopeBytes > DefaultMaxEnvelopeBytes)
        {
            throw new InvalidOperationException($"{SectionName}:MaxEnvelopeBytes must be between 1024 and {DefaultMaxEnvelopeBytes}.");
        }
    }
}
