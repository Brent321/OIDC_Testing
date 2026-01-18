using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authentication.WsFederation;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using IDP_Testing.Configuration;
using IDP_Testing.Services;
using Sustainsys.Saml2;
using Sustainsys.Saml2.AspNetCore2;
using Sustainsys.Saml2.Configuration;
using Sustainsys.Saml2.Metadata;
using Sustainsys.Saml2.WebSso;
using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;


namespace IDP_Testing.Extensions;

public static class AuthenticationExtensions
{
    public static IServiceCollection AddCustomAuthentication(this IServiceCollection services, WebApplicationBuilder builder)
    {
        var configuration = builder.Configuration;
        var environment = builder.Environment;

        // Register configuration options
        services.Configure<KeycloakOptions>(configuration.GetSection(KeycloakOptions.SectionName));
        services.Configure<Saml2ConfigurationOptions>(configuration.GetSection(Saml2ConfigurationOptions.SectionName));
        services.Configure<WsFederationConfigOptions>(configuration.GetSection(WsFederationConfigOptions.SectionName));

        // Enable all authentication schemes simultaneously
        var authBuilder = services
            .AddAuthentication(options =>
            {
                options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = null; // Let controllers choose explicitly
            })
            .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
            {
                options.Cookie.Name = ".AspNetCore.Cookies";
                options.ExpireTimeSpan = TimeSpan.FromHours(1);
                options.SlidingExpiration = true;
                options.Cookie.SameSite = SameSiteMode.Lax;
                options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
            });

        // Add all authentication schemes
        authBuilder.AddOidcAuthentication();
        authBuilder.AddSamlAuthentication(environment);
        authBuilder.AddWsFedAuthentication(); // NEW

        return services;
    }

    private static AuthenticationBuilder AddOidcAuthentication(this AuthenticationBuilder authBuilder)
    {
        return authBuilder.AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, options => { })
            .Services.AddOptions<OpenIdConnectOptions>(OpenIdConnectDefaults.AuthenticationScheme)
            .Configure<IOptions<KeycloakOptions>>((oidcOptions, keycloakOptionsAccessor) =>
            {
                var keycloakOptions = keycloakOptionsAccessor.Value;

                oidcOptions.Authority = keycloakOptions.Authority;
                oidcOptions.MetadataAddress = keycloakOptions.MetadataAddress;
                oidcOptions.RequireHttpsMetadata = keycloakOptions.RequireHttpsMetadata;
                oidcOptions.ClientId = keycloakOptions.ClientId;
                oidcOptions.ClientSecret = keycloakOptions.ClientSecret;
                oidcOptions.ResponseType = OpenIdConnectResponseType.Code;
                oidcOptions.SaveTokens = true;
                oidcOptions.GetClaimsFromUserInfoEndpoint = true;
                oidcOptions.MapInboundClaims = false;
                oidcOptions.TokenValidationParameters.NameClaimType = "preferred_username";
                oidcOptions.TokenValidationParameters.RoleClaimType = "roles";

                oidcOptions.Scope.Clear();
                oidcOptions.Scope.Add("openid");
                oidcOptions.Scope.Add("profile");
                oidcOptions.Scope.Add("email");
                oidcOptions.Scope.Add("roles");
                oidcOptions.Scope.Add("offline_access");

                oidcOptions.ClaimActions.MapJsonKey("preferred_username", "preferred_username");
                oidcOptions.ClaimActions.MapJsonKey("realm_access", "realm_access", "JsonElement");

                oidcOptions.CallbackPath = keycloakOptions.CallbackPath;

                // Handle redirect to identity provider for login
                oidcOptions.Events.OnRedirectToIdentityProvider = context =>
                {
                    // Check if we want to force re-authentication
                    if (context.Properties.Items.TryGetValue("prompt", out var promptValue))
                    {
                        context.ProtocolMessage.Prompt = promptValue;
                    }
                    
                    return Task.CompletedTask;
                };

                // Handle redirect to identity provider for sign out
                oidcOptions.Events.OnRedirectToIdentityProviderForSignOut = context =>
                {
                    // Get the id_token from the authentication properties
                    var idToken = context.Properties.GetTokenValue("id_token");
                    if (!string.IsNullOrWhiteSpace(idToken))
                    {
                        context.ProtocolMessage.IdTokenHint = idToken;
                    }

                    // Ensure post_logout_redirect_uri is set
                    if (string.IsNullOrEmpty(context.ProtocolMessage.PostLogoutRedirectUri))
                    {
                        context.ProtocolMessage.PostLogoutRedirectUri = keycloakOptions.PostLogoutRedirectUri;
                    }

                    return Task.CompletedTask;
                };

                // Handle token validation
                oidcOptions.Events.OnTokenValidated = context =>
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

                // Handle sign out
                oidcOptions.Events.OnSignedOutCallbackRedirect = context =>
                {
                    // Prevent automatic redirect, let the controller handle it
                    context.HandleResponse();
                    context.Response.Redirect(context.Options.SignedOutRedirectUri);
                    return Task.CompletedTask;
                };
            })
            .Services
            .AddAuthentication();
    }

    private static AuthenticationBuilder AddSamlAuthentication(this AuthenticationBuilder authBuilder, IWebHostEnvironment environment)
    {
        return authBuilder.AddSaml2(Saml2Defaults.Scheme, options => { })
            .Services.AddOptions<Saml2Options>(Saml2Defaults.Scheme)
            .Configure<IOptions<Saml2ConfigurationOptions>>((saml2Options, saml2ConfigOptionsAccessor) =>
            {
                var saml2ConfigOptions = saml2ConfigOptionsAccessor.Value;

                saml2Options.SPOptions.EntityId = new EntityId(saml2ConfigOptions.EntityId);
                saml2Options.SPOptions.ReturnUrl = new Uri(saml2ConfigOptions.EntityId);

                // Disable request signing in development
                if (environment.IsDevelopment())
                {
                    saml2Options.SPOptions.AuthenticateRequestSigningBehavior = SigningBehavior.Never;
                }
                else
                {
                    // In production, check if a certificate is configured
                    if (!string.IsNullOrWhiteSpace(saml2ConfigOptions.SigningCertificatePath) &&
                        File.Exists(saml2ConfigOptions.SigningCertificatePath))
                    {
                        var certificate = X509CertificateLoader.LoadPkcs12FromFile(
                            saml2ConfigOptions.SigningCertificatePath,
                            saml2ConfigOptions.SigningCertificatePassword,
                            X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet);

                        saml2Options.SPOptions.ServiceCertificates.Add(new ServiceCertificate
                        {
                            Certificate = certificate,
                            Use = CertificateUse.Signing
                        });
                    }
                    else
                    {
                        saml2Options.SPOptions.AuthenticateRequestSigningBehavior = SigningBehavior.Never;
                    }
                }

                var idp = new IdentityProvider(
                    new EntityId(saml2ConfigOptions.IdpEntityId),
                    saml2Options.SPOptions)
                {
                    SingleSignOnServiceUrl = new Uri(saml2ConfigOptions.IdpSingleSignOnUrl),
                    Binding = Saml2BindingType.HttpRedirect,
                    AllowUnsolicitedAuthnResponse = saml2ConfigOptions.AllowUnsolicitedAuthnResponse,
                    WantAuthnRequestsSigned = false
                };

                // Try to load metadata, but continue if it fails
                try
                {
                    idp.MetadataLocation = saml2ConfigOptions.IdpMetadataUrl;
                    idp.LoadMetadata = true;
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"Failed to load SAML metadata: {ex.Message}");
                }

                saml2Options.IdentityProviders.Add(idp);

                saml2Options.Notifications.AcsCommandResultCreated = (result, response) =>
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
            })
            .Services
            .AddAuthentication();
    }

    private static AuthenticationBuilder AddWsFedAuthentication(this AuthenticationBuilder authBuilder)
    {
        return authBuilder.AddWsFederation(WsFederationDefaults.AuthenticationScheme, options => { })
            .Services.AddOptions<Microsoft.AspNetCore.Authentication.WsFederation.WsFederationOptions>(WsFederationDefaults.AuthenticationScheme)
            .Configure<IOptions<WsFederationConfigOptions>>((wsFedOptions, wsFedConfigOptionsAccessor) =>
            {
                var wsFedConfig = wsFedConfigOptionsAccessor.Value;

                wsFedOptions.MetadataAddress = wsFedConfig.MetadataAddress;
                wsFedOptions.Wtrealm = wsFedConfig.Wtrealm;
                wsFedOptions.RequireHttpsMetadata = wsFedConfig.RequireHttpsMetadata;
                wsFedOptions.SaveTokens = wsFedConfig.SaveTokens;
                wsFedOptions.CallbackPath = wsFedConfig.CallbackPath;
                wsFedOptions.RemoteSignOutPath = wsFedConfig.RemoteSignOutPath;

                // Map claims
                wsFedOptions.TokenValidationParameters.NameClaimType = ClaimTypes.Name;
                wsFedOptions.TokenValidationParameters.RoleClaimType = ClaimTypes.Role;

                // Handle token validation
                wsFedOptions.Events.OnSecurityTokenValidated = context =>
                {
                    if (context.Principal?.Identity is ClaimsIdentity identity)
                    {
                        // Add any custom claim transformations here
                        Debug.WriteLine($"WS-Fed user authenticated: {identity.Name}");
                    }
                    return Task.CompletedTask;
                };
            })
            .Services
            .AddAuthentication();
    }
}