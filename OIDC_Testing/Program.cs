using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Server;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using OIDC_Testing.Components;
using System.Security.Claims;
using System.Text.Json;
using OIDC_Testing.Endpoints;
using Microsoft.AspNetCore.Authentication;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
})
    .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, options =>
    {
        var keycloak = builder.Configuration.GetSection("Keycloak");
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

                    AddRealmRoles(accessJwt, identity);
                    AddClientRoles(accessJwt, identity, keycloak["ClientId"]);
                }
            }

            return Task.CompletedTask;
        };
    });

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("RequireAppUser", policy => policy.RequireRole("app-user"));
    options.AddPolicy("RequireAppAdmin", policy => policy.RequireRole("app-admin"));
});

builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

builder.Services.AddCascadingAuthenticationState();
builder.Services.AddScoped<AuthenticationStateProvider, ServerAuthenticationStateProvider>();

var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    app.UseHsts();
}

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.UseStatusCodePages(context =>
{
    var statusCode = context.HttpContext.Response.StatusCode;
    if (statusCode == StatusCodes.Status403Forbidden)
    {
        context.HttpContext.Response.Redirect("/forbidden");
    }
    else if (statusCode == StatusCodes.Status404NotFound)
    {
        context.HttpContext.Response.Redirect("/not-found");
    }

    return Task.CompletedTask;
});

app.UseAntiforgery();

app.MapAuthenticationEndpoints();
app.MapRoleEndpoints();

app.MapStaticAssets();
app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

app.Run();

static void AddRealmRoles(JwtSecurityToken token, ClaimsIdentity identity)
{
    if (token.Payload.TryGetValue("realm_access", out var realmAccessObj) &&
        realmAccessObj is JsonElement realmAccessEl &&
        realmAccessEl.TryGetProperty("roles", out var rolesEl))
    {
        foreach (var roleEl in rolesEl.EnumerateArray())
        {
            if (roleEl.ValueKind == JsonValueKind.String)
            {
                var role = roleEl.GetString();
                if (!string.IsNullOrWhiteSpace(role))
                {
                    identity.AddClaim(new Claim(identity.RoleClaimType, role));
                }
            }
        }
    }
}

static void AddClientRoles(JwtSecurityToken token, ClaimsIdentity identity, string? clientId)
{
    if (string.IsNullOrWhiteSpace(clientId))
    {
        return;
    }

    if (token.Payload.TryGetValue("resource_access", out var resourceAccessObj) &&
        resourceAccessObj is JsonElement resourceAccessEl &&
        resourceAccessEl.TryGetProperty(clientId, out var clientAccessEl) &&
        clientAccessEl.TryGetProperty("roles", out var rolesEl))
    {
        foreach (var roleEl in rolesEl.EnumerateArray())
        {
            if (roleEl.ValueKind == JsonValueKind.String)
            {
                var role = roleEl.GetString();
                if (!string.IsNullOrWhiteSpace(role))
                {
                    identity.AddClaim(new Claim(identity.RoleClaimType, role));
                }
            }
        }
    }
}
