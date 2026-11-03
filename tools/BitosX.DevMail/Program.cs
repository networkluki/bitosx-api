using BitosX.Application.Accounts;
using BitosX.Application.Email;
using BitosX.Infrastructure.Email;
using BitosX.Infrastructure.Persistence;
using MySqlConnector;

// BitosX.DevMail — development-only outbox reader for the local live stack (tools/devstack/mail.sh).
//
//   BitosX.DevMail latest <verify|reset> <email>
//
// Prints ONE line on stdout: the token the latest pending (neither sent nor failed) outbox message of that type
// for that address carries — exactly the value after "#token=" in the emailed link (the payload stores the token,
// not the link). Exit 0 when found, 1 when there is none, 2 on a usage, configuration or integrity error.
//
// Inputs come from the environment, under the API's own configuration names, never from argv:
//   ConnectionStrings__Bitosx   the stack's database (runtime account)
//   Security__EmailOutboxKey    the stack's outbox key (decrypted with the Infrastructure's own protector)
// The tool refuses to run unless ASPNETCORE_ENVIRONMENT (or DOTNET_ENVIRONMENT) is Development or Testing; as in
// ASP.NET Core, an unset environment means Production.

const int Found = 0;
const int NoneFound = 1;
const int Error = 2;

var environment = Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT");
var dotnetEnvironment = Environment.GetEnvironmentVariable("DOTNET_ENVIRONMENT");
var effective = !string.IsNullOrWhiteSpace(environment) ? environment : dotnetEnvironment;
if (IsProduction(environment) || IsProduction(dotnetEnvironment)
    || !(string.Equals(effective, "Development", StringComparison.OrdinalIgnoreCase)
         || string.Equals(effective, "Testing", StringComparison.OrdinalIgnoreCase)))
{
    Console.Error.WriteLine("devmail: refused: runs only with ASPNETCORE_ENVIRONMENT=Development or Testing (never in Production).");
    return Error;
}

if (args.Length != 3 || !string.Equals(args[0], "latest", StringComparison.Ordinal))
{
    Console.Error.WriteLine("usage: BitosX.DevMail latest <verify|reset> <email>");
    return Error;
}

var messageType = args[1] switch
{
    "verify" => OutboxMessageTypes.EmailVerification,
    "reset" => OutboxMessageTypes.PasswordReset,
    _ => null,
};
if (messageType is null)
{
    Console.Error.WriteLine("devmail: the message kind must be 'verify' or 'reset'.");
    return Error;
}

if (string.IsNullOrWhiteSpace(args[2]))
{
    Console.Error.WriteLine("devmail: an email address is required.");
    return Error;
}

var connectionString = Environment.GetEnvironmentVariable("ConnectionStrings__Bitosx");
var outboxKey = Environment.GetEnvironmentVariable("Security__EmailOutboxKey");
if (string.IsNullOrWhiteSpace(connectionString) || string.IsNullOrWhiteSpace(outboxKey))
{
    Console.Error.WriteLine("devmail: ConnectionStrings__Bitosx and Security__EmailOutboxKey must be set (tools/devstack/mail.sh sets them).");
    return Error;
}

try
{
    var protector = new AesGcmOutboxPayloadProtector(new EmailOutboxCryptoOptions { Key = outboxKey });
    var normalizedEmail = EmailNormalizer.Normalize(args[2]);

    await using var connection = await new BitosxConnectionFactory(connectionString).OpenConnectionAsync();
    await using var command = connection.CreateCommand();
    // The account is matched by its normalized address (the registration may have used other letter case).
    command.CommandText =
        """
        SELECT o.id, o.recipient_email, o.payload_version, o.payload_nonce, o.payload_ciphertext, o.payload_tag
        FROM email_outbox o
        JOIN email_verification_challenges c ON c.id = o.challenge_id
        JOIN accounts a ON a.id = c.account_id
        WHERE a.normalized_email = @normalizedEmail
          AND o.message_type = @messageType
          AND o.sent_at IS NULL AND o.failed_at IS NULL
          AND o.payload_ciphertext IS NOT NULL
        ORDER BY o.created_at DESC, o.id DESC
        LIMIT 1;
        """;
    command.Parameters.AddWithValue("@normalizedEmail", normalizedEmail);
    command.Parameters.AddWithValue("@messageType", messageType);

    await using var reader = await command.ExecuteReaderAsync();
    if (!await reader.ReadAsync())
    {
        Console.Error.WriteLine($"devmail: no pending '{args[1]}' message for that address.");
        return NoneFound;
    }

    var id = reader.GetGuid(0);
    var recipient = reader.GetString(1);
    var version = reader.GetByte(2);
    var sealedPayload = new ProtectedOutboxPayload(version, (byte[])reader[3], (byte[])reader[4], (byte[])reader[5]);

    if (!protector.TryUnprotect(sealedPayload, new OutboxAad(id, version, messageType, recipient), out var payload) || payload is null)
    {
        Console.Error.WriteLine("devmail: the outbox payload did not decrypt (wrong Security__EmailOutboxKey for this database?).");
        return Error;
    }

    Console.Out.WriteLine(payload.TokenBase64Url);
    return Found;
}
catch (Exception ex) when (ex is MySqlException or InvalidOperationException or ArgumentException)
{
    // Type and driver message only: never the connection string or the key.
    Console.Error.WriteLine($"devmail: failed ({ex.GetType().Name}): {ex.Message}");
    return Error;
}

static bool IsProduction(string? value) => string.Equals(value?.Trim(), "Production", StringComparison.OrdinalIgnoreCase);
