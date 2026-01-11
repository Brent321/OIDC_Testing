namespace OIDC_Testing.Services;

public interface IAccessTokenProvider
{
    Task<string?> GetAccessTokenAsync();
}