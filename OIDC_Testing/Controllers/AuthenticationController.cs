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
    private readonly ILogger<AuthenticationController> _logger;

    public AuthenticationController(IConfiguration configuration, ILogger<AuthenticationController> logger)
    {
        _configuration = configuration;
        _logger = logger;
    }

    [HttpGet("login")]
    public IActionResult Login(string? returnUrl, string? scheme)
    {
        var authMode = _configuration["AuthenticationMode"]?.ToUpperInvariant() ?? "OIDC";
        var authScheme = scheme ?? (authMode == "SAML" ? Saml2Defaults.Scheme : OpenIdConnectDefaults.AuthenticationScheme);
        
        var redirectUri = string.IsNullOrWhiteSpace(returnUrl) ? "/" : returnUrl;
        
        _logger.LogInformation("Login initiated with scheme: {Scheme}, redirect: {RedirectUri}", authScheme, redirectUri);
        
        return Challenge(
            new AuthenticationProperties { RedirectUri = redirectUri },
            authScheme);
    }

    [HttpGet("login-oidc")]
    public IActionResult LoginOidc(string? returnUrl)
    {
        var redirectUri = string.IsNullOrWhiteSpace(returnUrl) ? "/" : returnUrl;
        
        _logger.LogInformation("OIDC login initiated, redirect: {RedirectUri}", redirectUri);
        
        return Challenge(
            new AuthenticationProperties { RedirectUri = redirectUri },
            OpenIdConnectDefaults.AuthenticationScheme);
    }

    [HttpGet("login-saml")]
    public IActionResult LoginSaml(string? returnUrl)
    {
        var redirectUri = string.IsNullOrWhiteSpace(returnUrl) ? "/" : returnUrl;
        
        _logger.LogInformation("SAML login initiated, redirect: {RedirectUri}", redirectUri);
        
        return Challenge(
            new AuthenticationProperties { RedirectUri = redirectUri },
            Saml2Defaults.Scheme);
    }

    [HttpGet("logout")]
    public async Task<IActionResult> Logout()
    {
        var authenticateResult = await HttpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        
        // Check if user is authenticated
        if (authenticateResult?.Succeeded != true)
        {
            _logger.LogWarning("Logout attempted but no authenticated user found");
            return Redirect("/");
        }

        var userName = authenticateResult.Principal?.Identity?.Name;
        
        // Determine authentication mode from configuration as fallback
        var authMode = _configuration["AuthenticationMode"]?.ToUpperInvariant() ?? "OIDC";
        var isSaml = authMode == "SAML";
        
        // Try to detect SAML by checking for SAML-specific claims
        if (authenticateResult.Principal?.Identity is System.Security.Claims.ClaimsIdentity claimsIdentity)
        {
            // SAML responses typically have claims with specific namespaces
            var hasSamlClaims = claimsIdentity.Claims.Any(c => 
                c.Type.StartsWith("http://schemas.xmlsoap.org/") || 
                c.Type.StartsWith("http://schemas.microsoft.com/ws/2008/06/identity/claims/"));
            
            if (hasSamlClaims)
            {
                isSaml = true;
            }
        }
        
        if (isSaml)
        {
            _logger.LogInformation("SAML logout initiated for user: {UserName}", userName);
            
            return SignOut(
                new AuthenticationProperties { RedirectUri = "/" },
                CookieAuthenticationDefaults.AuthenticationScheme,
                Saml2Defaults.Scheme);
        }
        
        // OIDC logout
        var idToken = authenticateResult.Properties?.GetTokenValue("id_token");
        
        _logger.LogInformation("OIDC logout initiated for user: {UserName}, ID Token present: {HasIdToken}", 
            userName, !string.IsNullOrWhiteSpace(idToken));
        
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        
        var keycloakAuthority = _configuration["Keycloak:Authority"];
        var clientId = _configuration["Keycloak:ClientId"];
        var postLogoutUri = _configuration["Keycloak:PostLogoutRedirectUri"] ?? "https://localhost:7235/";
        
        var logoutUrl = $"{keycloakAuthority}/protocol/openid-connect/logout?post_logout_redirect_uri={Uri.EscapeDataString(postLogoutUri)}&client_id={clientId}";
        
        if (!string.IsNullOrWhiteSpace(idToken))
        {
            logoutUrl += $"&id_token_hint={Uri.EscapeDataString(idToken)}";
        }
        
        return Redirect(logoutUrl);
    }

    [HttpGet("clear-cookies")]
    public IActionResult ClearCookies()
    {
        _logger.LogInformation("Clearing all authentication cookies");
        
        // Clear all auth cookies - useful for development
        Response.Cookies.Delete(".AspNetCore.Cookies");
        Response.Cookies.Delete(".AspNetCore.Cookies.OIDC");
        Response.Cookies.Delete(".AspNetCore.Cookies.SAML");
        
        return Ok(new { Message = "All authentication cookies cleared. Please refresh the page." });
    }
}