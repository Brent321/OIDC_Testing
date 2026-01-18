using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authentication.WsFederation;
using Microsoft.AspNetCore.Mvc;
using Sustainsys.Saml2.AspNetCore2;

namespace IDP_Testing.Controllers;

[Route("authentication")]
public class AuthenticationController : Controller
{
    [HttpGet("login")]
    public IActionResult Login(string? authMode = null, string? returnUrl = null)
    {
        // Determine which authentication scheme to use
        var scheme = authMode?.ToLower() switch
        {
            "oidc" or "keycloak" => OpenIdConnectDefaults.AuthenticationScheme,
            "saml" or "saml2" => Saml2Defaults.Scheme,
            "wsfed" or "adfs" => WsFederationDefaults.AuthenticationScheme,
            _ => OpenIdConnectDefaults.AuthenticationScheme // Default
        };

        var properties = new AuthenticationProperties
        {
            RedirectUri = returnUrl ?? Url.Content("~/")
        };

        return Challenge(properties, scheme);
    }

    [HttpGet("logout")]
    public async Task<IActionResult> Logout()
    {
        var authenticationType = User.Identity?.AuthenticationType;
        
        // Determine which scheme was used for authentication
        var scheme = authenticationType switch
        {
            "AuthenticationTypes.Federation" or "WsFederation" => WsFederationDefaults.AuthenticationScheme,
            "Saml2" => Saml2Defaults.Scheme,
            _ => OpenIdConnectDefaults.AuthenticationScheme
        };

        // Sign out from cookie
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

        // Sign out from the identity provider
        return SignOut(new AuthenticationProperties
        {
            RedirectUri = Url.Content("~/")
        }, scheme);
    }

    [HttpGet("signout-callback-oidc")]
    public IActionResult SignoutCallbackOidc()
    {
        return Redirect("~/");
    }

    [HttpGet("signout-callback-wsfed")]
    public IActionResult SignoutCallbackWsFed()
    {
        return Redirect("~/");
    }
}