namespace BitosX.Application.Security;

/// <summary>Outcome of verifying a password against a stored hash.</summary>
public enum PasswordVerificationResult
{
    /// <summary>Password matches and the stored parameters are current.</summary>
    Success,

    /// <summary>Password does not match.</summary>
    Failed,

    /// <summary>Password matches but the stored parameters are weaker than current policy.</summary>
    NeedsRehash,

    /// <summary>The stored hash is malformed, unsupported, or outside safe verification bounds.</summary>
    InvalidHashFormat,
}

/// <summary>
/// Hashes and verifies BitosX account passwords (Argon2id). Independent of the
/// vault KDF. Never stores or logs plaintext.
/// </summary>
public interface IAccountPasswordHasher
{
    /// <summary>Produces a self-describing PHC hash string for the password.</summary>
    string Hash(string password);

    /// <summary>
    /// Verifies a password against a stored PHC hash. Validates the encoded
    /// parameters against safe resource bounds BEFORE running Argon2; a hostile
    /// hash returns <see cref="PasswordVerificationResult.InvalidHashFormat"/>
    /// without performing expensive work.
    /// </summary>
    PasswordVerificationResult Verify(string password, string encodedHash);
}
