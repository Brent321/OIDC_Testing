using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace OIDC_Testing.Controllers;

[ApiController]
[Route("api/[controller]")]
public class RolesController : ControllerBase
{
    [HttpGet("user")]
    [Authorize(Policy = "RequireAppUser")]
    public IActionResult GetUser()
    {
        return Ok(new
        {
            Message = "You have access to the app-user endpoint.",
            User = User.Identity?.Name
        });
    }

    [HttpGet("admin")]
    [Authorize(Policy = "RequireAppAdmin")]
    public IActionResult GetAdmin()
    {
        return Ok(new
        {
            Message = "You have access to the app-admin endpoint.",
            User = User.Identity?.Name
        });
    }
}