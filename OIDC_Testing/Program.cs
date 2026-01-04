using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Server;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using OIDC_Testing.Components;
using System.Security.Claims;
using System.Text.Json;
using System.Net.Http;
using System.Collections.Generic;

var builder = WebApplication.CreateBuilder(args);

// Add HttpClientFactory for token refresh
builder.Services.AddHttpClient();

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
        // Request offline access to get a refresh token
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

        options.Events.OnRedirectToIdentityProviderForSignOut = context =>
        {
            var idToken = context.Properties?.GetTokenValue("id_token");
            if (!string.IsNullOrWhiteSpace(idToken))
            {
                context.ProtocolMessage.IdTokenHint = idToken;
            }

            var request = context.Request;
            var postLogoutUri = $"{request.Scheme}://{request.Host}/logged-out";
            context.ProtocolMessage.PostLogoutRedirectUri = postLogoutUri;

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

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    app.UseHsts();
}

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

// Send 403 to /forbidden and 404 to /not-found
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

app.MapGet("/login", (HttpContext httpContext, string? returnUrl) =>
{
    var redirectUri = string.IsNullOrWhiteSpace(returnUrl) ? "/" : returnUrl;
    return Results.Challenge(
        new AuthenticationProperties { RedirectUri = redirectUri },
        new[] { OpenIdConnectDefaults.AuthenticationScheme });
});

app.MapGet("/logout", async (
    HttpContext httpContext,
    IHttpClientFactory httpClientFactory,
    IConfiguration configuration) =>
{
    var props = new AuthenticationProperties();
    var keycloak = configuration.GetSection("Keycloak");

    // 1. Get the refresh token from the session
    var refreshToken = await httpContext.GetTokenAsync("refresh_token");

    if (!string.IsNullOrWhiteSpace(refreshToken))
    {
        // 2. Use the refresh token to get a new id_token
        var client = httpClientFactory.CreateClient();
        var tokenEndpoint = $"{keycloak["Authority"]}/protocol/openid-connect/token";

        var requestBody = new Dictionary<string, string>
        {
            ["client_id"] = keycloak["ClientId"]!,
            ["client_secret"] = keycloak["ClientSecret"]!,
            ["grant_type"] = "refresh_token",
            ["refresh_token"] = refreshToken
        };

        var response = await client.PostAsync(tokenEndpoint, new FormUrlEncodedContent(requestBody));

        if (response.IsSuccessStatusCode)
        {
            var content = await response.Content.ReadFromJsonAsync<JsonElement>();
            var newIdToken = content.GetProperty("id_token").GetString();

            if (!string.IsNullOrWhiteSpace(newIdToken))
            {
                // 3. Store the fresh id_token for the sign-out process
                props.StoreTokens(new[]
                {
                    new AuthenticationToken { Name = "id_token", Value = newIdToken }
                });
            }
        }
    }

    // 4. Only sign out from Keycloak. The local cookie will be cleared in /logged-out.
    await httpContext.SignOutAsync(OpenIdConnectDefaults.AuthenticationScheme, props);
});


app.MapGet("/logged-out", async (HttpContext httpContext) =>
{
    // This endpoint is the redirect target from Keycloak.
    // Now, we clear the local session cookie.
    await httpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    return Results.Redirect("/");
});


app.MapGet("/api/roles/user", [Authorize(Policy = "RequireAppUser")] (ClaimsPrincipal user) =>
{
    return Results.Ok(new
    {
        Message = "You have access to the app-user endpoint.",
        User = user.Identity?.Name
    });
});

app.MapGet("/api/roles/admin", [Authorize(Policy = "RequireAppAdmin")] (ClaimsPrincipal user) =>
{
    return Results.Ok(new
    {
        Message = "You have access to the app-admin endpoint.",
        User = user.Identity?.Name
    });
});

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
