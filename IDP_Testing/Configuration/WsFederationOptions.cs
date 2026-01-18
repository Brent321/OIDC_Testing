namespace IDP_Testing.Configuration;

public class WsFederationOptions
{
    public const string SectionName = "WsFederation";
    
    public string MetadataAddress { get; set; } = string.Empty;
    public string Wtrealm { get; set; } = string.Empty;
    public string Authority { get; set; } = string.Empty;
    public string CallbackPath { get; set; } = "/signin-wsfed";
    public string RemoteSignOutPath { get; set; } = "/signout-wsfed";
    public bool RequireHttpsMetadata { get; set; } = true;
    public bool SaveTokens { get; set; } = true;
}