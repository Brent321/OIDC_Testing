using Microsoft.AspNetCore.Authorization;

namespace OIDC_Testing.Extensions;

public static class AuthorizationExtensions
{
    public static IServiceCollection AddCustomAuthorization(this IServiceCollection services)
    {
        services.AddAuthorizationBuilder()
            .AddPolicy("RequireAppUser", policy => policy.RequireRole("app-user"))
            .AddPolicy("RequireAppAdmin", policy => policy.RequireRole("app-admin"));

        return services;
    }
}