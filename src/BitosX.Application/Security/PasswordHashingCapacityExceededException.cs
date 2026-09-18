namespace BitosX.Application.Security;

/// <summary>
/// Signals that a password-hashing (Argon2) operation could not be ADMITTED — the bounded work gate was
/// saturated (execution slots + queue full) or the bounded wait timed out. This is deliberately DISTINCT
/// from a password mismatch (<see cref="PasswordVerificationResult.Failed"/>): capacity exhaustion must
/// never be reported as invalid credentials.
///
/// Defined in the Application layer so Infrastructure (which performs hashing) can throw it and the API
/// (which maps it to a generic 503) can catch it, without either taking a dependency on the other's
/// concrete types. It carries NO password, email, account id, timing, queue-depth, or secret data.
/// </summary>
public sealed class PasswordHashingCapacityExceededException : Exception
{
    public PasswordHashingCapacityExceededException()
        : base("Password hashing capacity exceeded.")
    {
    }
}
