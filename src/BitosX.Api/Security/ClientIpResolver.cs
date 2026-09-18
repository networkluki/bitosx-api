using System.Net;
using System.Net.Sockets;

namespace BitosX.Api.Security;

/// <summary>
/// Resolves the authoritative client IP for rate-limit partitioning. The trust boundary is established
/// by <c>UseForwardedHeaders</c> (loopback Apache proxy only) BEFORE this runs, so the authoritative
/// address is <see cref="ConnectionInfo.RemoteIpAddress"/> — never a raw header. IPv4-mapped IPv6
/// addresses are folded to their IPv4 form so one client cannot obtain two buckets.
/// </summary>
public static class ClientIpResolver
{
    /// <summary>
    /// Produces a stable partition key from the post-forwarding remote IP. Returns false when no usable
    /// non-loopback client IP is available (null or loopback) — the caller fails closed in hardened mode
    /// rather than bucketing everyone under a shared/loopback key.
    /// </summary>
    public static bool TryResolveUsableClientIp(HttpContext context, out string partitionKey)
    {
        partitionKey = string.Empty;
        var address = context.Connection.RemoteIpAddress;
        if (address is null)
        {
            return false;
        }

        var normalized = Normalize(address);
        if (IPAddress.IsLoopback(normalized))
        {
            return false;
        }

        partitionKey = normalized.ToString();
        return true;
    }

    /// <summary>Folds an IPv4-mapped IPv6 address (::ffff:a.b.c.d) to its canonical IPv4 form.</summary>
    private static IPAddress Normalize(IPAddress address)
        => address.AddressFamily == AddressFamily.InterNetworkV6 && address.IsIPv4MappedToIPv6
            ? address.MapToIPv4()
            : address;
}
