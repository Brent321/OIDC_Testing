namespace OIDC_Testing.Configuration;

public class AuthenticationModeOptions
{
    public const string SectionName = "AuthenticationMode";

    public string Mode { get; set; } = "OIDC";

    public bool IsSaml => Mode?.Equals("SAML", StringComparison.OrdinalIgnoreCase) == true;
    public bool IsOidc => !IsSaml;
}