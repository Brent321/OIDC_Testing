using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text.Json;

namespace OIDC_Testing.Services;

public static class KeycloakRoleMapper
{
    public static void AddRealmRoles(JwtSecurityToken token, ClaimsIdentity identity)
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

    public static void AddClientRoles(JwtSecurityToken token, ClaimsIdentity identity, string? clientId)
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
}