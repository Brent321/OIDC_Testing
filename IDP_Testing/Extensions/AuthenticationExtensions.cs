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
        services.Configure<AuthenticationModeOptions>(configuration.GetSection(AuthenticationModeOptions.SectionName));
        services.Configure<KeycloakOptions>(configuration.GetSection(KeycloakOptions.SectionName));
        services.Configure<Saml2ConfigurationOptions>(configuration.GetSection(Saml2ConfigurationOptions.SectionName));
        services.Configure<WsFederationConfigOptions>(configuration.GetSection(WsFederationConfigOptions.SectionName));

        // Get the configured authentication mode
        var authMode = configuration.GetSection(AuthenticationModeOptions.SectionName).Get<AuthenticationModeOptions>()?.Mode ?? "OIDC";
        
        Console.WriteLine($"Configuring authentication with mode: {authMode}");

        // Base authentication with cookies
        var authBuilder = services
            .AddAuthentication(options =>
            {
                options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = GetChallengeScheme(authMode);
            })
            .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
            {
                options.Cookie.Name = ".AspNetCore.Cookies";
                options.ExpireTimeSpan = TimeSpan.FromHours(1);
                options.SlidingExpiration = true;
                options.Cookie.SameSite = SameSiteMode.Lax;
                options.Cookie.SecurePolicy = CookieSecurePolicy.Always;

                // Preserve the original authentication type
                options.Events.OnSigningIn = context =>
                {
                    if (context.Principal?.Identity is ClaimsIdentity identity)
                    {
                        // Determine the authentication scheme from the authentication properties or ticket
                        string? scheme = null;
                        context.Properties?.Items.TryGetValue(".AuthScheme", out scheme);
                        scheme ??= identity.AuthenticationType;

                        if (!string.IsNullOrEmpty(scheme))
                        {
                            // Create a new identity with the original authentication type
                            var newIdentity = new ClaimsIdentity(
                                identity.Claims,
                                scheme,
                                identity.NameClaimType,
                                identity.RoleClaimType);

                            context.Principal = new ClaimsPrincipal(newIdentity);
                            Console.WriteLine($"Cookie OnSigningIn: Preserved authentication type as '{scheme}'");
                        }
                    }

                    return Task.CompletedTask;
                };
            });

        // Add only the configured authentication scheme
        switch (authMode.ToUpperInvariant())
        {
            case "OIDC":
                authBuilder.AddOidcAuthentication();
                break;
            case "SAML":
                authBuilder.AddSamlAuthentication(environment);
                break;
            case "WSFED":
                authBuilder.AddWsFedAuthentication();
                break;
            default:
                throw new InvalidOperationException($"Unknown authentication mode: {authMode}. Valid values are: OIDC, SAML, WSFED");
        }

        return services;
    }

    private static string? GetChallengeScheme(string authMode) => authMode.ToUpperInvariant() switch
    {
        "OIDC" => OpenIdConnectDefaults.AuthenticationScheme,
        "SAML" => Saml2Defaults.Scheme,
        "WSFED" => WsFederationDefaults.AuthenticationScheme,
        _ => null
    };

    private static AuthenticationBuilder AddOidcAuthentication(this AuthenticationBuilder authBuilder)
    {
        return authBuilder
            .AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, options => { })
            .Services
            .AddOptions<OpenIdConnectOptions>(OpenIdConnectDefaults.AuthenticationScheme)
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
                    if (context.Properties.Items.TryGetValue("prompt", out var promptValue))
                    {
                        context.ProtocolMessage.Prompt = promptValue;
                    }
                    
                    return Task.CompletedTask;
                };

                // Handle redirect to identity provider for sign out
                oidcOptions.Events.OnRedirectToIdentityProviderForSignOut = context =>
                {
                    Console.WriteLine($"🔍 Event fired - Properties.Items count: {context.Properties?.Items?.Count ?? 0}");
    
                    string? idToken = null;
    
                    if (context.Properties?.Items?.TryGetValue("id_token", out var itemToken) == true)
                    {
                        idToken = itemToken;
                        Console.WriteLine("Found id_token in Items");
                    }
    
                    if (!string.IsNullOrWhiteSpace(idToken))
                    {
                        context.ProtocolMessage.IdTokenHint = idToken;
                        Console.WriteLine("✅ Set IdTokenHint on protocol message");
                    }
                    else
                    {
                        Console.WriteLine("⚠️ Warning: id_token not found during logout");
                    }

                    if (string.IsNullOrEmpty(context.ProtocolMessage.PostLogoutRedirectUri))
                    {
                        context.ProtocolMessage.PostLogoutRedirectUri = keycloakOptions.PostLogoutRedirectUri;
                    }
    
                    return Task.CompletedTask;
                };

                // Handle token validation - explicitly set authentication type
                oidcOptions.Events.OnTokenValidated = context =>
                {
                    if (context.Principal?.Identity is ClaimsIdentity identity)
                    {
                        // Create a new identity with explicit authentication type
                        var newIdentity = new ClaimsIdentity(
                            identity.Claims,
                            OpenIdConnectDefaults.AuthenticationScheme,
                            identity.NameClaimType,
                            identity.RoleClaimType);

                        var accessToken = context.TokenEndpointResponse?.AccessToken;
                        if (!string.IsNullOrWhiteSpace(accessToken))
                        {
                            var handler = new JwtSecurityTokenHandler();
                            var accessJwt = handler.ReadJwtToken(accessToken);

                            KeycloakRoleMapper.AddRealmRoles(accessJwt, newIdentity);
                            KeycloakRoleMapper.AddClientRoles(accessJwt, newIdentity, keycloakOptions.ClientId);
                        }

                        context.Principal = new ClaimsPrincipal(newIdentity);
                        
                        // Store the authentication scheme for the cookie handler
                        context.Properties!.Items[".AuthScheme"] = OpenIdConnectDefaults.AuthenticationScheme;
                        
                        Console.WriteLine($"OIDC OnTokenValidated: Set authentication type to '{OpenIdConnectDefaults.AuthenticationScheme}'");
                    }

                    return Task.CompletedTask;
                };

                // Handle sign out callback
                oidcOptions.Events.OnSignedOutCallbackRedirect = context =>
                {
                    context.Response.Redirect(keycloakOptions.PostLogoutRedirectUri);
                    context.HandleResponse();
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

                if (environment.IsDevelopment())
                {
                    saml2Options.SPOptions.AuthenticateRequestSigningBehavior = SigningBehavior.Never;
                }
                else
                {
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
                        // Create a new ClaimsIdentity with the correct authentication type
                        var newIdentity = new ClaimsIdentity(
                            identity.Claims,
                            Saml2Defaults.Scheme,
                            identity.NameClaimType,
                            identity.RoleClaimType);

                        // Process role claims
                        var roleClaims = identity.FindAll("http://schemas.microsoft.com/ws/2008/06/identity/claims/role")
                            .Concat(identity.FindAll("Role"))
                            .ToList();

                        foreach (var roleClaim in roleClaims)
                        {
                            if (!string.IsNullOrWhiteSpace(roleClaim.Value))
                            {
                                newIdentity.AddClaim(new Claim(newIdentity.RoleClaimType ?? ClaimTypes.Role, roleClaim.Value));
                            }
                        }

                        // Add a claim to mark the authentication scheme for the cookie handler
                        newIdentity.AddClaim(new Claim(".AuthScheme", Saml2Defaults.Scheme));

                        result.Principal = new ClaimsPrincipal(newIdentity);
                        
                        Console.WriteLine($"SAML AcsCommandResultCreated: Set authentication type to '{Saml2Defaults.Scheme}'");
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
                var wsFedConfigOptions = wsFedConfigOptionsAccessor.Value;

                wsFedOptions.MetadataAddress = wsFedConfigOptions.MetadataAddress;
                wsFedOptions.Wtrealm = wsFedConfigOptions.Wtrealm;
                wsFedOptions.RequireHttpsMetadata = wsFedConfigOptions.RequireHttpsMetadata;
                wsFedOptions.SaveTokens = wsFedConfigOptions.SaveTokens;
                wsFedOptions.CallbackPath = wsFedConfigOptions.CallbackPath;
                wsFedOptions.RemoteSignOutPath = wsFedConfigOptions.RemoteSignOutPath;
                
                wsFedOptions.TokenValidationParameters.NameClaimType = "name";
                wsFedOptions.TokenValidationParameters.RoleClaimType = ClaimTypes.Role;
                
                wsFedOptions.Events.OnSecurityTokenValidated = context =>
                {
                    if (context.Principal?.Identity is ClaimsIdentity identity)
                    {
                        // Create a new identity with explicit authentication type
                        var newIdentity = new ClaimsIdentity(
                            identity.Claims,
                            WsFederationDefaults.AuthenticationScheme,
                            identity.NameClaimType,
                            identity.RoleClaimType);

                        context.Principal = new ClaimsPrincipal(newIdentity);
                        
                        // Store the authentication scheme for the cookie handler
                        context.Properties!.Items[".AuthScheme"] = WsFederationDefaults.AuthenticationScheme;
                        
                        Console.WriteLine($"WsFed OnSecurityTokenValidated: Set authentication type to '{WsFederationDefaults.AuthenticationScheme}'");
                    }

                    return Task.CompletedTask;
                };
            })
            .Services
            .AddAuthentication();
    }
}