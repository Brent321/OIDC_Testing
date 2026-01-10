using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using OIDC_Testing.Configuration;
using OIDC_Testing.Services;
using Sustainsys.Saml2;
using Sustainsys.Saml2.AspNetCore2;
using Sustainsys.Saml2.Configuration;
using Sustainsys.Saml2.Metadata;
using Sustainsys.Saml2.WebSso;
using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;

namespace OIDC_Testing.Extensions;

public static class AuthenticationExtensions
{
    public static IServiceCollection AddCustomAuthentication(this IServiceCollection services, WebApplicationBuilder builder)
    {
        var configuration = builder.Configuration;
        var environment = builder.Environment;

        // Register configuration options
        services.Configure<KeycloakOptions>(configuration.GetSection(KeycloakOptions.SectionName));
        services.Configure<Saml2ConfigurationOptions>(configuration.GetSection(Saml2ConfigurationOptions.SectionName));

        var authMode = configuration["AuthenticationMode"]?.ToUpperInvariant() ?? "OIDC";

        var authBuilder = services
            .AddAuthentication(options =>
            {
                options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = authMode == "SAML" ?
                    Saml2Defaults.Scheme :
                    OpenIdConnectDefaults.AuthenticationScheme;
            })
            .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
            {
                options.Cookie.Name = $".AspNetCore.Cookies.{authMode}";
                options.ExpireTimeSpan = TimeSpan.FromHours(1);
                options.SlidingExpiration = true;
            });

        authBuilder.AddOidcAuthentication(services);
        authBuilder.AddSamlAuthentication(services, environment);

        return services;
    }

    private static AuthenticationBuilder AddOidcAuthentication(this AuthenticationBuilder authBuilder, IServiceCollection services)
    {
        return authBuilder.AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, options =>
        {
            // Use a service provider to resolve options if needed
            var sp = services.BuildServiceProvider();
            var keycloakOptions = sp.GetRequiredService<IOptions<KeycloakOptions>>().Value;

            options.Authority = keycloakOptions.Authority;
            options.MetadataAddress = keycloakOptions.MetadataAddress;
            options.RequireHttpsMetadata = keycloakOptions.RequireHttpsMetadata;
            options.ClientId = keycloakOptions.ClientId;
            options.ClientSecret = keycloakOptions.ClientSecret;
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

            options.CallbackPath = keycloakOptions.CallbackPath;

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
                        KeycloakRoleMapper.AddClientRoles(accessJwt, identity, keycloakOptions.ClientId);
                    }
                }

                return Task.CompletedTask;
            };
        });
    }

    private static AuthenticationBuilder AddSamlAuthentication(this AuthenticationBuilder authBuilder, IServiceCollection services, IWebHostEnvironment environment)
    {
        return authBuilder.AddSaml2(Saml2Defaults.Scheme, options =>
        {
            // Use a service provider to resolve options if needed
            var sp = services.BuildServiceProvider();
            var saml2Options = sp.GetRequiredService<IOptions<Saml2ConfigurationOptions>>().Value;

            options.SPOptions.EntityId = new EntityId(saml2Options.EntityId);
            options.SPOptions.ReturnUrl = new Uri(saml2Options.EntityId);

            // Disable request signing in development
            if (environment.IsDevelopment())
            {
                options.SPOptions.AuthenticateRequestSigningBehavior = SigningBehavior.Never;
            }
            else
            {
                // In production, check if a certificate is configured
                if (!string.IsNullOrWhiteSpace(saml2Options.SigningCertificatePath) &&
                    File.Exists(saml2Options.SigningCertificatePath))
                {
                    var certificate = new X509Certificate2(
                        saml2Options.SigningCertificatePath,
                        saml2Options.SigningCertificatePassword,
                        X509KeyStorageFlags.MachineKeySet);

                    options.SPOptions.ServiceCertificates.Add(new ServiceCertificate
                    {
                        Certificate = certificate,
                        Use = CertificateUse.Signing
                    });
                }
                else
                {
                    options.SPOptions.AuthenticateRequestSigningBehavior = SigningBehavior.Never;
                }
            }

            var idp = new IdentityProvider(
                new EntityId(saml2Options.IdpEntityId),
                options.SPOptions)
            {
                SingleSignOnServiceUrl = new Uri(saml2Options.IdpSingleSignOnUrl),
                Binding = Saml2BindingType.HttpRedirect,
                AllowUnsolicitedAuthnResponse = saml2Options.AllowUnsolicitedAuthnResponse,
                WantAuthnRequestsSigned = false
            };

            // Try to load metadata, but continue if it fails
            try
            {
                idp.MetadataLocation = saml2Options.IdpMetadataUrl;
                idp.LoadMetadata = true;
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Failed to load SAML metadata: {ex.Message}");
            }

            options.IdentityProviders.Add(idp);

            options.Notifications.AcsCommandResultCreated = (result, response) =>
            {
                if (result.Principal?.Identity is ClaimsIdentity identity)
                {
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