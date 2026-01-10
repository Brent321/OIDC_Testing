using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Policy;

namespace OIDC_Testing.Extensions;

public static class AuthorizationExtensions
{
    public static IServiceCollection AddCustomAuthorization(this IServiceCollection services)
    {
        services.AddAuthorizationBuilder()
            .AddPolicy("RequireAppUser", policy => policy.RequireRole("app-user"))
            .AddPolicy("RequireAppAdmin", policy => policy.RequireRole("app-admin"));

        // Configure authorization to handle SAML authentication provider limitations
        services.AddSingleton<IAuthorizationMiddlewareResultHandler, CustomAuthorizationMiddlewareResultHandler>();

        return services;
    }
}

public class CustomAuthorizationMiddlewareResultHandler : IAuthorizationMiddlewareResultHandler
{
    private readonly AuthorizationMiddlewareResultHandler _defaultHandler = new();

    public async Task HandleAsync(
        RequestDelegate next,
        HttpContext context,
        AuthorizationPolicy policy,
        PolicyAuthorizationResult authorizeResult)
    {
        // If authorization failed and the user is authenticated
        if (!authorizeResult.Succeeded && context.User.Identity?.IsAuthenticated == true)
        {
            // Redirect to forbidden page instead of calling ForbidAsync
            context.Response.Redirect("/forbidden");
            return;
        }

        // Otherwise, use the default handler
        await _defaultHandler.HandleAsync(next, context, policy, authorizeResult);
    }
}