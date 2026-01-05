using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;

namespace OIDC_Testing.Endpoints;

public static class AuthenticationEndpoints
{
    public static IEndpointRouteBuilder MapAuthenticationEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet("/login", (HttpContext httpContext, string? returnUrl) =>
        {
            var redirectUri = string.IsNullOrWhiteSpace(returnUrl) ? "/" : returnUrl;
            return Results.Challenge(
                new AuthenticationProperties { RedirectUri = redirectUri },
                [OpenIdConnectDefaults.AuthenticationScheme]);
        });

        endpoints.MapGet("/logout", async (HttpContext httpContext) =>
        {
            var authenticateResult = await httpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            
            var idToken = authenticateResult?.Properties?.GetTokenValue("id_token");
            
            Console.WriteLine($"Logout initiated. ID Token found: {!string.IsNullOrWhiteSpace(idToken)}");
            
            await httpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            
            var keycloakAuthority = httpContext.RequestServices.GetRequiredService<IConfiguration>()["Keycloak:Authority"];
            var clientId = httpContext.RequestServices.GetRequiredService<IConfiguration>()["Keycloak:ClientId"];
            var postLogoutUri = "https://localhost:7235/";
            
            var logoutUrl = $"{keycloakAuthority}/protocol/openid-connect/logout?post_logout_redirect_uri={Uri.EscapeDataString(postLogoutUri)}&client_id={clientId}";
            
            if (!string.IsNullOrWhiteSpace(idToken))
            {
                logoutUrl += $"&id_token_hint={Uri.EscapeDataString(idToken)}";
            }
            
            return Results.Redirect(logoutUrl);
        });

        return endpoints;
    }
}