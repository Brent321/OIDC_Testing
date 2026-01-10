using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using OIDC_Testing.Services;
using Sustainsys.Saml2;
using Sustainsys.Saml2.AspNetCore2;
using Sustainsys.Saml2.Metadata;
using Sustainsys.Saml2.Configuration;
using Sustainsys.Saml2.WebSso;

namespace OIDC_Testing.Extensions;

public static class AuthenticationExtensions
{
    public static IServiceCollection AddCustomAuthentication(this IServiceCollection services, IConfiguration configuration, IWebHostEnvironment environment)
    {
        var authMode = configuration["AuthenticationMode"]?.ToUpperInvariant() ?? "OIDC";

        var authBuilder = services.AddAuthentication(options =>
        {
            options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            options.DefaultChallengeScheme = authMode == "SAML" ? Saml2Defaults.Scheme : OpenIdConnectDefaults.AuthenticationScheme;
        })
            .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
            {
                // Use different cookie names for different auth modes to prevent conflicts
                options.Cookie.Name = $".AspNetCore.Cookies.{authMode}";
                options.ExpireTimeSpan = TimeSpan.FromHours(1);
                options.SlidingExpiration = true;
            });

        authBuilder.AddOidcAuthentication(configuration);
        authBuilder.AddSamlAuthentication(configuration, environment);

        return services;
    }

    private static AuthenticationBuilder AddOidcAuthentication(this AuthenticationBuilder authBuilder, IConfiguration configuration)
    {
        return authBuilder.AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, options =>
        {
            var keycloak = configuration.GetSection("Keycloak");
            options.Authority = keycloak["Authority"];
            options.MetadataAddress = keycloak["MetadataAddress"];
            options.RequireHttpsMetadata = bool.TryParse(keycloak["RequireHttpsMetadata"], out var requireHttps) && requireHttps;
            options.ClientId = keycloak["ClientId"];
            options.ClientSecret = keycloak["ClientSecret"];
            options.ResponseType = OpenIdConnectResponseType.Code;
            options.SaveTokens = true;
            options.GetClaimsFromUserInfoEndpoint = true;
            options.MapInboundClaims = false;
            options.TokenValidationParameters.NameClaimType = "preferred_username";
            options.TokenValidationParameters.RoleClaimType = "roles";

            options.Scope.Clear();
            options.Scope.Add("openid");
            options.Scope.Add("profile");
            options.Scope.Add("email");
            options.Scope.Add("roles");
            options.Scope.Add("offline_access");

            options.ClaimActions.MapJsonKey("preferred_username", "preferred_username");
            options.ClaimActions.MapJsonKey("realm_access", "realm_access", "JsonElement");

            options.CallbackPath = "/signin-oidc";

            options.Events.OnTokenValidated = context =>
            {
                if (context.Principal?.Identity is ClaimsIdentity identity)
                {
                    var accessToken = context.TokenEndpointResponse?.AccessToken;
                    if (!string.IsNullOrWhiteSpace(accessToken))
                    {
                        var handler = new JwtSecurityTokenHandler();
                        var accessJwt = handler.ReadJwtToken(accessToken);

                        KeycloakRoleMapper.AddRealmRoles(accessJwt, identity);
                        KeycloakRoleMapper.AddClientRoles(accessJwt, identity, keycloak["ClientId"]);
                    }
                }

                return Task.CompletedTask;
            };
        });
    }

    private static AuthenticationBuilder AddSamlAuthentication(this AuthenticationBuilder authBuilder, IConfiguration configuration, IWebHostEnvironment environment)
    {
        return authBuilder.AddSaml2(Saml2Defaults.Scheme, options =>
        {
            var saml2Config = configuration.GetSection("Saml2");
            
            options.SPOptions.EntityId = new EntityId(saml2Config["EntityId"] ?? "https://localhost:7235");
            options.SPOptions.ReturnUrl = new Uri(saml2Config["EntityId"] ?? "https://localhost:7235");
            
            // Disable request signing in development
            if (environment.IsDevelopment())
            {
                options.SPOptions.AuthenticateRequestSigningBehavior = SigningBehavior.Never;
            }
            else
            {
                // In production, check if a certificate is configured
                var certPath = saml2Config["SigningCertificatePath"];
                var certPassword = saml2Config["SigningCertificatePassword"];
                
                if (!string.IsNullOrWhiteSpace(certPath) && File.Exists(certPath))
                {
                    var certificate = new System.Security.Cryptography.X509Certificates.X509Certificate2(
                        certPath, 
                        certPassword,
                        System.Security.Cryptography.X509Certificates.X509KeyStorageFlags.MachineKeySet);
                    
                    options.SPOptions.ServiceCertificates.Add(new ServiceCertificate
                    {
                        Certificate = certificate,
                        Use = CertificateUse.Signing
                    });
                }
                else
                {
                    // Fall back to not signing if no certificate is provided
                    options.SPOptions.AuthenticateRequestSigningBehavior = SigningBehavior.Never;
                }
            }
            
            var idp = new IdentityProvider(
                new EntityId(saml2Config["IdpEntityId"] ?? "http://localhost:8080/realms/blazor-dev"),
                options.SPOptions)
            {
                SingleSignOnServiceUrl = new Uri(saml2Config["IdpSingleSignOnUrl"] ?? "http://localhost:8080/realms/blazor-dev/protocol/saml"),
                Binding = Saml2BindingType.HttpRedirect,
                AllowUnsolicitedAuthnResponse = bool.TryParse(saml2Config["AllowUnsolicitedAuthnResponse"], out var allowUnsolicited) && allowUnsolicited,
                WantAuthnRequestsSigned = false
            };

            // Try to load metadata, but continue if it fails
            try
            {
                idp.MetadataLocation = saml2Config["IdpMetadataUrl"] ?? "http://localhost:8080/realms/blazor-dev/protocol/saml/descriptor";
                idp.LoadMetadata = true;
            }
            catch
            {
                // Metadata loading failed, continue with manual configuration
            }

            options.IdentityProviders.Add(idp);
            
            options.Notifications.AcsCommandResultCreated = (result, response) =>
            {
                if (result.Principal?.Identity is ClaimsIdentity identity)
                {
                    // Map SAML role claims to the expected role claim type
                    var roleClaims = identity.FindAll("http://schemas.microsoft.com/ws/2008/06/identity/claims/role")
                        .Concat(identity.FindAll("Role"))
                        .ToList();
                    
                    foreach (var roleClaim in roleClaims)
                    {
                        if (!string.IsNullOrWhiteSpace(roleClaim.Value))
                        {
                            identity.AddClaim(new Claim(identity.RoleClaimType ?? ClaimTypes.Role, roleClaim.Value));
                        }
                    }
                }
            };
        });
    }
}