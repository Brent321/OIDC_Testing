using Microsoft.Extensions.Options;
using OIDC_Testing.Configuration;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace OIDC_Testing.Services;

public interface IDocumentSigningService
{
    Task<DocumentSignatureResult> SignDocumentAsync(byte[] documentData, string accessToken, string documentName);
    Task<bool> VerifySignatureAsync(byte[] documentData, string signature, string documentName);
    
    // New methods for JSON signing
    Task<DocumentSignatureResult> SignJsonAsync(string jsonData, string accessToken, string identifier = "json-data");
    Task<bool> VerifyJsonSignatureAsync(string jsonData, string signature, string identifier = "json-data");
}

public class DocumentSigningService : IDocumentSigningService
{
    private readonly HttpClient _httpClient;
    private readonly KeycloakOptions _keycloakOptions;
    private readonly ILogger<DocumentSigningService> _logger;

    public DocumentSigningService(
        IHttpClientFactory httpClientFactory,
        IOptions<KeycloakOptions> keycloakOptions,
        ILogger<DocumentSigningService> logger)
    {
        _httpClient = httpClientFactory.CreateClient();
        _keycloakOptions = keycloakOptions.Value;
        _logger = logger;
    }

    public async Task<DocumentSignatureResult> SignDocumentAsync(byte[] documentData, string accessToken, string documentName)
    {
        try
        {
            // Create a hash of the document
            var documentHash = ComputeDocumentHash(documentData);

            // Create signature metadata
            var signatureMetadata = new SignatureMetadata
            {
                DocumentName = documentName,
                DocumentHash = documentHash,
                SignedAt = DateTimeOffset.UtcNow,
                DocumentSize = documentData.Length,
                DataType = "document"
            };

            // Get user info from Keycloak to include in signature
            var userInfo = await GetUserInfoAsync(accessToken);
            signatureMetadata.SignedBy = userInfo.PreferredUsername ?? "unknown";
            signatureMetadata.SignedByEmail = userInfo.Email;

            // Create the payload to sign
            var signaturePayload = JsonSerializer.Serialize(signatureMetadata);

            // Sign the payload using the document hash and access token
            var signature = CreateSignature(signaturePayload, accessToken);

            return new DocumentSignatureResult
            {
                Success = true,
                Signature = signature,
                Metadata = signatureMetadata,
                Message = "Document signed successfully"
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error signing document: {DocumentName}", documentName);
            return new DocumentSignatureResult
            {
                Success = false,
                Message = $"Failed to sign document: {ex.Message}"
            };
        }
    }

    public async Task<DocumentSignatureResult> SignJsonAsync(string jsonData, string accessToken, string identifier = "json-data")
    {
        try
        {
            // Convert JSON string to bytes for hashing
            var jsonBytes = Encoding.UTF8.GetBytes(jsonData);
            var jsonHash = ComputeDocumentHash(jsonBytes);

            // Validate JSON format
            try
            {
                JsonDocument.Parse(jsonData);
            }
            catch (JsonException)
            {
                return new DocumentSignatureResult
                {
                    Success = false,
                    Message = "Invalid JSON format"
                };
            }

            // Create signature metadata
            var signatureMetadata = new SignatureMetadata
            {
                DocumentName = identifier,
                DocumentHash = jsonHash,
                SignedAt = DateTimeOffset.UtcNow,
                DocumentSize = jsonBytes.Length,
                DataType = "json"
            };

            // Get user info from Keycloak
            var userInfo = await GetUserInfoAsync(accessToken);
            signatureMetadata.SignedBy = userInfo.PreferredUsername ?? "unknown";
            signatureMetadata.SignedByEmail = userInfo.Email;

            // Create the payload to sign
            var signaturePayload = JsonSerializer.Serialize(signatureMetadata);

            // Sign the payload
            var signature = CreateSignature(signaturePayload, accessToken);

            return new DocumentSignatureResult
            {
                Success = true,
                Signature = signature,
                Metadata = signatureMetadata,
                Message = "JSON data signed successfully"
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error signing JSON data: {Identifier}", identifier);
            return new DocumentSignatureResult
            {
                Success = false,
                Message = $"Failed to sign JSON data: {ex.Message}"
            };
        }
    }

    public Task<bool> VerifySignatureAsync(byte[] documentData, string signature, string documentName)
    {
        try
        {
            // Compute the current hash of the document
            var currentHash = ComputeDocumentHash(documentData);

            // Decode the signature to extract metadata
            var decodedSignature = Convert.FromBase64String(signature);
            var signatureJson = Encoding.UTF8.GetString(decodedSignature);
            var metadata = JsonSerializer.Deserialize<SignatureMetadata>(signatureJson);

            if (metadata == null)
            {
                return Task.FromResult(false);
            }

            // Verify the document hash matches
            var isValid = metadata.DocumentHash == currentHash && 
                         metadata.DocumentName == documentName;

            return Task.FromResult(isValid);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error verifying signature for document: {DocumentName}", documentName);
            return Task.FromResult(false);
        }
    }

    public Task<bool> VerifyJsonSignatureAsync(string jsonData, string signature, string identifier = "json-data")
    {
        try
        {
            // Convert JSON to bytes and compute hash
            var jsonBytes = Encoding.UTF8.GetBytes(jsonData);
            var currentHash = ComputeDocumentHash(jsonBytes);

            // Decode the signature to extract metadata
            var decodedSignature = Convert.FromBase64String(signature);
            var signatureJson = Encoding.UTF8.GetString(decodedSignature);
            var metadata = JsonSerializer.Deserialize<SignatureMetadata>(signatureJson);

            if (metadata == null)
            {
                return Task.FromResult(false);
            }

            // Verify the JSON hash matches and it's a JSON type signature
            var isValid = metadata.DocumentHash == currentHash && 
                         metadata.DocumentName == identifier &&
                         metadata.DataType == "json";

            return Task.FromResult(isValid);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error verifying JSON signature: {Identifier}", identifier);
            return Task.FromResult(false);
        }
    }

    private string ComputeDocumentHash(byte[] documentData)
    {
        using var sha256 = SHA256.Create();
        var hashBytes = sha256.ComputeHash(documentData);
        return Convert.ToBase64String(hashBytes);
    }

    private string CreateSignature(string payload, string accessToken)
    {
        // Combine payload with a portion of the access token to create a verifiable signature
        // In production, you would use proper cryptographic signing with Keycloak's signing keys
        var signatureData = $"{payload}|{GetTokenSignature(accessToken)}";
        var signatureBytes = Encoding.UTF8.GetBytes(signatureData);
        return Convert.ToBase64String(signatureBytes);
    }

    private string GetTokenSignature(string accessToken)
    {
        // Extract the signature portion of the JWT token
        var parts = accessToken.Split('.');
        return parts.Length >= 3 ? parts[2] : string.Empty;
    }

    private async Task<KeycloakUserInfo> GetUserInfoAsync(string accessToken)
    {
        try
        {
            var userInfoEndpoint = $"{_keycloakOptions.Authority}/protocol/openid-connect/userinfo";
            
            var request = new HttpRequestMessage(HttpMethod.Get, userInfoEndpoint);
            request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);

            var response = await _httpClient.SendAsync(request);
            response.EnsureSuccessStatusCode();

            var userInfoJson = await response.Content.ReadAsStringAsync();
            return JsonSerializer.Deserialize<KeycloakUserInfo>(userInfoJson) ?? new KeycloakUserInfo();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error retrieving user info from Keycloak");
            return new KeycloakUserInfo();
        }
    }
}

public class SignatureMetadata
{
    public string DocumentName { get; set; } = string.Empty;
    public string DocumentHash { get; set; } = string.Empty;
    public string SignedBy { get; set; } = string.Empty;
    public string? SignedByEmail { get; set; }
    public DateTimeOffset SignedAt { get; set; }
    public long DocumentSize { get; set; }
    public string DataType { get; set; } = "document"; // "document" or "json"
}

public class DocumentSignatureResult
{
    public bool Success { get; set; }
    public string Signature { get; set; } = string.Empty;
    public SignatureMetadata? Metadata { get; set; }
    public string Message { get; set; } = string.Empty;
}

public class KeycloakUserInfo
{
    public string? Sub { get; set; }
    public string? PreferredUsername { get; set; }
    public string? Email { get; set; }
    public bool? EmailVerified { get; set; }
    public string? Name { get; set; }
}