using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Server;
using OIDC_Testing.Services;

namespace OIDC_Testing.Extensions;

public static class BlazorExtensions
{
    public static IServiceCollection AddBlazorServices(this IServiceCollection services)
    {
        services.AddRazorComponents()
            .AddInteractiveServerComponents();

        services.AddCascadingAuthenticationState();
        services.AddScoped<AuthenticationStateProvider, ServerAuthenticationStateProvider>();
        
        // Add HttpClient factory for proper HttpClient management
        services.AddHttpClient();

        // Add HttpContextAccessor for accessing HttpContext in Blazor components
        services.AddHttpContextAccessor();

        // Register access token provider service
        services.AddScoped<IAccessTokenProvider, AccessTokenProvider>();

        // Register document signing service
        services.AddScoped<IDocumentSigningService, DocumentSigningService>();

        return services;
    }
}