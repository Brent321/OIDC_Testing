namespace OIDC_Testing.Configuration;

public class Saml2ConfigurationOptions
{
    public const string SectionName = "Saml2";

    public string EntityId { get; set; } = string.Empty;
    public string IdpEntityId { get; set; } = string.Empty;
    public string IdpMetadataUrl { get; set; } = string.Empty;
    public string IdpSingleSignOnUrl { get; set; } = string.Empty;
    public string IdpSingleLogoutUrl { get; set; } = string.Empty;
    public string SigningCertificatePath { get; set; } = string.Empty;
    public string SigningCertificatePassword { get; set; } = string.Empty;
    public bool AllowUnsolicitedAuthnResponse { get; set; }
}