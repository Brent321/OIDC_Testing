namespace IDP_Testing.Configuration;

public class AuthenticationModeOptions
{
    public const string SectionName = "Authentication";

    public string Mode { get; set; } = "OIDC"; // OIDC, SAML, or WSFED

    public string GetDisplayName() => Mode.ToUpperInvariant() switch
    {
        "OIDC" => "OpenID Connect",
        "SAML" => "SAML 2.0",
        "WSFED" => "WS-Federation",
        _ => "Unknown"
    };
}