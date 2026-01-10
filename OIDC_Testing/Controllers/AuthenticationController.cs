using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Mvc;
using Sustainsys.Saml2.AspNetCore2;

namespace OIDC_Testing.Controllers;

[ApiController]
[Route("[controller]")]
public class AuthenticationController : ControllerBase
{
    private readonly IConfiguration _configuration;

    public AuthenticationController(IConfiguration configuration)
    {
        _configuration = configuration;
    }

    [HttpGet("login")]
    public IActionResult Login(string? returnUrl, string? scheme)
    {
        var authMode = _configuration["AuthenticationMode"]?.ToUpperInvariant() ?? "OIDC";
        var authScheme = scheme ?? (authMode == "SAML" ? Saml2Defaults.Scheme : OpenIdConnectDefaults.AuthenticationScheme);
        
        var redirectUri = string.IsNullOrWhiteSpace(returnUrl) ? "/" : returnUrl;
        return Challenge(
            new AuthenticationProperties { RedirectUri = redirectUri },
            authScheme);
    }

    [HttpGet("login-oidc")]
    public IActionResult LoginOidc(string? returnUrl)
    {
        var redirectUri = string.IsNullOrWhiteSpace(returnUrl) ? "/" : returnUrl;
        return Challenge(
            new AuthenticationProperties { RedirectUri = redirectUri },
            OpenIdConnectDefaults.AuthenticationScheme);
    }

    [HttpGet("login-saml")]
    public IActionResult LoginSaml(string? returnUrl)
    {
        var redirectUri = string.IsNullOrWhiteSpace(returnUrl) ? "/" : returnUrl;
        return Challenge(
            new AuthenticationProperties { RedirectUri = redirectUri },
            Saml2Defaults.Scheme);
    }

    [HttpGet("logout")]
    public async Task<IActionResult> Logout()
    {
        var authenticateResult = await HttpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        
        var authScheme = authenticateResult?.Properties?.Items[".AuthScheme"];
        var isSaml = authScheme == Saml2Defaults.Scheme;
        
        if (isSaml)
        {
            return SignOut(
                new AuthenticationProperties { RedirectUri = "/" },
                CookieAuthenticationDefaults.AuthenticationScheme,
                Saml2Defaults.Scheme);
        }
        
        var idToken = authenticateResult?.Properties?.GetTokenValue("id_token");
        
        Console.WriteLine($"Logout initiated. ID Token found: {!string.IsNullOrWhiteSpace(idToken)}");
        
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        
        var keycloakAuthority = _configuration["Keycloak:Authority"];
        var clientId = _configuration["Keycloak:ClientId"];
        var postLogoutUri = "https://localhost:7235/";
        
        var logoutUrl = $"{keycloakAuthority}/protocol/openid-connect/logout?post_logout_redirect_uri={Uri.EscapeDataString(postLogoutUri)}&client_id={clientId}";
        
        if (!string.IsNullOrWhiteSpace(idToken))
        {
            logoutUrl += $"&id_token_hint={Uri.EscapeDataString(idToken)}";
        }
        
        return Redirect(logoutUrl);
    }
}