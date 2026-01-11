using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using IDP_Testing.Data;
using IDP_Testing.Models;
using IDP_Testing.Configuration;

namespace IDP_Testing.Services;

public interface IConfigurationService
{
    Task<List<ConfigurationEntry>> GetAllAsync();
    Task<ConfigurationEntry?> GetByKeyAsync(string key);
    Task<bool> AddOrUpdateAsync(string key, string? value);
    Task<bool> DeleteAsync(string key);
    Task ReloadConfigurationAsync();
    Task ResetFromAppSettingsAsync();
}

public class ConfigurationService : IConfigurationService
{
    private readonly ApplicationDbContext _dbContext;
    private readonly IConfiguration _configuration;
    private readonly IConfigurationRoot _configurationRoot;

    public ConfigurationService(
        ApplicationDbContext dbContext,
        IConfiguration configuration)
    {
        _dbContext = dbContext;
        _configuration = configuration;
        _configurationRoot = (IConfigurationRoot)configuration;
    }

    public async Task<List<ConfigurationEntry>> GetAllAsync()
    {
        return await _dbContext.ConfigurationEntries
            .OrderBy(c => c.Key)
            .ToListAsync();
    }

    public async Task<ConfigurationEntry?> GetByKeyAsync(string key)
    {
        return await _dbContext.ConfigurationEntries
            .FirstOrDefaultAsync(c => c.Key == key);
    }

    public async Task<bool> AddOrUpdateAsync(string key, string? value)
    {
        var existing = await _dbContext.ConfigurationEntries
            .FirstOrDefaultAsync(c => c.Key == key);

        if (existing != null)
        {
            existing.Value = value;
            existing.LastModified = DateTime.UtcNow;
        }
        else
        {
            _dbContext.ConfigurationEntries.Add(new ConfigurationEntry
            {
                Key = key,
                Value = value,
                LastModified = DateTime.UtcNow
            });
        }

        await _dbContext.SaveChangesAsync();
        return true;
    }

    public async Task<bool> DeleteAsync(string key)
    {
        var entry = await _dbContext.ConfigurationEntries
            .FirstOrDefaultAsync(c => c.Key == key);

        if (entry == null)
            return false;

        _dbContext.ConfigurationEntries.Remove(entry);
        await _dbContext.SaveChangesAsync();
        return true;
    }

    public async Task ReloadConfigurationAsync()
    {
        // Find the EFCore configuration provider and reload it
        var efCoreProvider = _configurationRoot.Providers
            .OfType<EFCoreConfigurationProvider>()
            .FirstOrDefault();

        if (efCoreProvider != null)
        {
            await Task.Run(() => efCoreProvider.Reload());
        }
    }

    public async Task ResetFromAppSettingsAsync()
    {
        // Clear all database configurations
        var allEntries = await _dbContext.ConfigurationEntries.ToListAsync();
        _dbContext.ConfigurationEntries.RemoveRange(allEntries);
        await _dbContext.SaveChangesAsync();

        // Reload configuration (will now use appsettings values)
        await ReloadConfigurationAsync();
    }
}