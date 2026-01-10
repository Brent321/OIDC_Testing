using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using OIDC_Testing.Configuration;
using Sustainsys.Saml2.AspNetCore2;

namespace OIDC_Testing.Controllers;

[ApiController]
[Route("[controller]")]
public class AuthenticationController : ControllerBase
{
    private readonly IConfiguration _configuration;
    private readonly ILogger<AuthenticationController> _logger;
    private readonly KeycloakOptions _keycloakOptions;

    public AuthenticationController(
        IConfiguration configuration,
        ILogger<AuthenticationController> logger,
        IOptions<KeycloakOptions> keycloakOptions)
    {
        _configuration = configuration;
        _logger = logger;
        _keycloakOptions = keycloakOptions.Value;
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

        if (authenticateResult?.Succeeded != true)
        {
            _logger.LogWarning("Logout attempted but no authenticated user found");
            return Redirect("/");
        }

        var userName = authenticateResult.Principal?.Identity?.Name;
        var authMode = _configuration["AuthenticationMode"]?.ToUpperInvariant() ?? "OIDC";
        var isSaml = authMode == "SAML";

        if (authenticateResult.Principal?.Identity is System.Security.Claims.ClaimsIdentity claimsIdentity)
        {
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

        var idToken = authenticateResult.Properties?.GetTokenValue("id_token");

        _logger.LogInformation("OIDC logout initiated for user: {UserName}, ID Token present: {HasIdToken}",
            userName, !string.IsNullOrWhiteSpace(idToken));

        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

        var postLogoutUri = _keycloakOptions.PostLogoutRedirectUri;
        var logoutUrl = $"{_keycloakOptions.Authority}/protocol/openid-connect/logout?post_logout_redirect_uri={Uri.EscapeDataString(postLogoutUri)}&client_id={_keycloakOptions.ClientId}";

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

        Response.Cookies.Delete(".AspNetCore.Cookies");
        Response.Cookies.Delete(".AspNetCore.Cookies.OIDC");
        Response.Cookies.Delete(".AspNetCore.Cookies.SAML");

        return Ok(new { Message = "All authentication cookies cleared. Please refresh the page." });
    }
}