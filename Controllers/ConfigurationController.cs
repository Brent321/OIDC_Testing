using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using IDP_Testing.Services;
using IDP_Testing.Models;

namespace IDP_Testing.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize(Roles = "Admin")]
public class ConfigurationController : ControllerBase
{
    private readonly IConfigurationService _configService;

    public ConfigurationController(IConfigurationService configService)
    {
        _configService = configService;
    }

    [HttpGet]
    public async Task<ActionResult<List<ConfigurationEntry>>> GetAll()
    {
        return Ok(await _configService.GetAllAsync());
    }

    [HttpGet("{key}")]
    public async Task<ActionResult<ConfigurationEntry>> Get(string key)
    {
        var entry = await _configService.GetByKeyAsync(key);
        if (entry == null)
            return NotFound();
        return Ok(entry);
    }

    [HttpPost]
    public async Task<ActionResult> AddOrUpdate([FromBody] ConfigurationEntry entry)
    {
        await _configService.AddOrUpdateAsync(entry.Key, entry.Value);
        return Ok();
    }

    [HttpDelete("{key}")]
    public async Task<ActionResult> Delete(string key)
    {
        var result = await _configService.DeleteAsync(key);
        if (!result)
            return NotFound();
        return Ok();
    }

    [HttpPost("reload")]
    public async Task<ActionResult> Reload()
    {
        await _configService.ReloadConfigurationAsync();
        return Ok();
    }

    [HttpPost("reset")]
    public async Task<ActionResult> ResetToAppSettings()
    {
        await _configService.ResetFromAppSettingsAsync();
        return Ok();
    }
}