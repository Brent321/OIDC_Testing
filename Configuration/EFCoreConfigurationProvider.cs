using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using IDP_Testing.Data;

namespace IDP_Testing.Configuration;

public class EFCoreConfigurationProvider : ConfigurationProvider
{
    private readonly Action<DbContextOptionsBuilder> _optionsAction;

    public EFCoreConfigurationProvider(Action<DbContextOptionsBuilder> optionsAction)
    {
        _optionsAction = optionsAction;
    }

    public override void Load()
    {
        var builder = new DbContextOptionsBuilder<ApplicationDbContext>();
        _optionsAction(builder);

        using var dbContext = new ApplicationDbContext(builder.Options);
        
        // Ensure database exists
        dbContext.Database.EnsureCreated();

        Data = dbContext.ConfigurationEntries
            .AsNoTracking()
            .ToDictionary(c => c.Key, c => c.Value ?? string.Empty, StringComparer.OrdinalIgnoreCase);
    }

    public void Reload()
    {
        Load();
        OnReload();
    }
}