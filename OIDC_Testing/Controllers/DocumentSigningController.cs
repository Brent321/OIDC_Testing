using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using OIDC_Testing.Services;
using System.Text.Json;

namespace OIDC_Testing.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize]
public class DocumentSigningController : ControllerBase
{
    private readonly IDocumentSigningService _signingService;
    private readonly ILogger<DocumentSigningController> _logger;

    public DocumentSigningController(
        IDocumentSigningService signingService,
        ILogger<DocumentSigningController> logger)
    {
        _signingService = signingService;
        _logger = logger;
    }

    [HttpPost("sign")]
    public async Task<IActionResult> SignDocument([FromForm] SignDocumentRequest request)
    {
        if (request.Document == null || request.Document.Length == 0)
        {
            return BadRequest(new { message = "No document provided" });
        }

        var accessToken = await HttpContext.GetTokenAsync("access_token");
        if (string.IsNullOrEmpty(accessToken))
        {
            return Unauthorized(new { message = "No access token available" });
        }

        using var memoryStream = new MemoryStream();
        await request.Document.CopyToAsync(memoryStream);
        var documentData = memoryStream.ToArray();

        var result = await _signingService.SignDocumentAsync(documentData, accessToken, request.Document.FileName);

        if (!result.Success)
        {
            return BadRequest(new { message = result.Message });
        }

        return Ok(new
        {
            signature = result.Signature,
            metadata = result.Metadata,
            message = result.Message
        });
    }

    [HttpPost("sign-json")]
    public async Task<IActionResult> SignJson([FromBody] SignJsonRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.JsonData))
        {
            return BadRequest(new { message = "No JSON data provided" });
        }

        // Validate JSON format
        try
        {
            JsonDocument.Parse(request.JsonData);
        }
        catch (JsonException ex)
        {
            return BadRequest(new { message = $"Invalid JSON format: {ex.Message}" });
        }

        var accessToken = await HttpContext.GetTokenAsync("access_token");
        if (string.IsNullOrEmpty(accessToken))
        {
            return Unauthorized(new { message = "No access token available" });
        }

        var result = await _signingService.SignJsonAsync(request.JsonData, accessToken, request.Identifier ?? "json-data");

        if (!result.Success)
        {
            return BadRequest(new { message = result.Message });
        }

        return Ok(new
        {
            signature = result.Signature,
            metadata = result.Metadata,
            message = result.Message
        });
    }

    [HttpPost("verify")]
    public async Task<IActionResult> VerifyDocument([FromForm] VerifyDocumentRequest request)
    {
        if (request.Document == null || request.Document.Length == 0)
        {
            return BadRequest(new { message = "No document provided" });
        }

        if (string.IsNullOrEmpty(request.Signature))
        {
            return BadRequest(new { message = "No signature provided" });
        }

        using var memoryStream = new MemoryStream();
        await request.Document.CopyToAsync(memoryStream);
        var documentData = memoryStream.ToArray();

        var isValid = await _signingService.VerifySignatureAsync(documentData, request.Signature, request.Document.FileName);

        return Ok(new
        {
            valid = isValid,
            message = isValid ? "Signature is valid" : "Signature is invalid or document has been modified"
        });
    }

    [HttpPost("verify-json")]
    public async Task<IActionResult> VerifyJson([FromBody] VerifyJsonRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.JsonData))
        {
            return BadRequest(new { message = "No JSON data provided" });
        }

        if (string.IsNullOrWhiteSpace(request.Signature))
        {
            return BadRequest(new { message = "No signature provided" });
        }

        // Validate JSON format
        try
        {
            JsonDocument.Parse(request.JsonData);
        }
        catch (JsonException ex)
        {
            return BadRequest(new { message = $"Invalid JSON format: {ex.Message}" });
        }

        var isValid = await _signingService.VerifyJsonSignatureAsync(request.JsonData, request.Signature, request.Identifier ?? "json-data");

        return Ok(new
        {
            valid = isValid,
            message = isValid ? "JSON signature is valid" : "Signature is invalid or JSON has been modified"
        });
    }
}

public class SignDocumentRequest
{
    public IFormFile Document { get; set; } = null!;
}

public class SignJsonRequest
{
    public string JsonData { get; set; } = string.Empty;
    public string? Identifier { get; set; }
}

public class VerifyDocumentRequest
{
    public IFormFile Document { get; set; } = null!;
    public string Signature { get; set; } = string.Empty;
}

public class VerifyJsonRequest
{
    public string JsonData { get; set; } = string.Empty;
    public string Signature { get; set; } = string.Empty;
    public string? Identifier { get; set; }
}