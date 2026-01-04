using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;

namespace OIDC_Testing.Endpoints;

public static class RoleEndpoints
{
    public static IEndpointRouteBuilder MapRoleEndpoints(this IEndpointRouteBuilder endpoints)
    {
        var roleGroup = endpoints.MapGroup("/api/roles");

        roleGroup.MapGet("/user", [Authorize(Policy = "RequireAppUser")] (ClaimsPrincipal user) =>
        {
            return Results.Ok(new
            {
                Message = "You have access to the app-user endpoint.",
                User = user.Identity?.Name
            });
        });

        roleGroup.MapGet("/admin", [Authorize(Policy = "RequireAppAdmin")] (ClaimsPrincipal user) =>
        {
            return Results.Ok(new
            {
                Message = "You have access to the app-admin endpoint.",
                User = user.Identity?.Name
            });
        });

        return endpoints;
    }
}