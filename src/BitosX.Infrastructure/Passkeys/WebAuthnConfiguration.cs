using BitosX.Application.Passkeys;
using Microsoft.Extensions.Configuration;

namespace BitosX.Infrastructure.Passkeys;

/// <summary>Binds <c>Security:WebAuthn</c> (non-secret). <c>Origins</c> is a list (array), or one string of origins separated by ';' or ','.</summary>
public static class WebAuthnConfiguration
{
    /// <summary>The bound section, or null when it is absent (every key blank). A configured section is validated (throws when invalid).</summary>
    public static WebAuthnOptions? BindAndValidate(IConfiguration configuration, bool allowLocalhost)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        var section = configuration.GetSection(WebAuthnOptions.SectionName);
        var originsSection = section.GetSection("Origins");
        var origins = originsSection.GetChildren().Select(c => c.Value ?? string.Empty).ToList();
        if (!string.IsNullOrWhiteSpace(originsSection.Value))
        {
            origins.AddRange(originsSection.Value.Split([';', ','], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
        }

        var options = new WebAuthnOptions
        {
            RelyingPartyId = section["RelyingPartyId"] ?? string.Empty,
            RelyingPartyName = section["RelyingPartyName"] ?? string.Empty,
            Origins = origins,
        };

        if (!options.IsConfigured)
        {
            return null;
        }

        options.Validate(allowLocalhost);
        return options;
    }
}
