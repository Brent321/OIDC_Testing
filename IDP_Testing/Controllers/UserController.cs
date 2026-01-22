using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authentication;
using System.Security.Claims;

namespace IDP_Testing.Controllers;

[Route("api/[controller]")]
[ApiController]
public class UserController : ControllerBase
{
    [HttpGet]
    public async Task<IActionResult> GetUser()
    {
        if (User.Identity?.IsAuthenticated == true)
        {
            var claims = User.Claims
                .GroupBy(c => c.Type)
                .ToDictionary(g => g.Key, g => g.Count() > 1 
                    ? (object)g.Select(c => c.Value).ToArray() 
                    : g.First().Value);
            
            return Ok(new
            {
                IsAuthenticated = true,
                Name = User.Identity.Name ?? User.FindFirst("preferred_username")?.Value ?? "Unknown User",
                Claims = claims
            });
        }

        return Ok(new
        {
            IsAuthenticated = false
        });
    }
}
