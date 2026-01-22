using System.Reflection;
using System.Runtime.Loader;

namespace IDP_Testing.Services;

public class PluginService
{
    private readonly string _pluginsPath;
    private readonly ILogger<PluginService> _logger;
    private readonly List<Assembly> _loadedAssemblies = new();

    public IReadOnlyList<Assembly> LoadedAssemblies => _loadedAssemblies.AsReadOnly();

    public PluginService(IWebHostEnvironment env, ILogger<PluginService> logger)
    {
        _pluginsPath = Path.Combine(env.ContentRootPath, "Plugins");
        _logger = logger;
        
        // Ensure directory exists
        if (!Directory.Exists(_pluginsPath))
        {
            Directory.CreateDirectory(_pluginsPath);
        }
    }

    public void LoadPlugins()
    {
        _logger.LogInformation("Loading plugins from {Path}", _pluginsPath);
        
        var dllFiles = Directory.GetFiles(_pluginsPath, "*.dll");
        foreach (var dllPath in dllFiles)
        {
            try
            {
                // Basic loading. For more isolation, use AssemblyLoadContext.
                // Note: On Windows, this may lock the file. 
                var assembly = Assembly.LoadFrom(dllPath);
                
                // Check if it has any razor components (optional check)
                if (!_loadedAssemblies.Contains(assembly))
                {
                    _loadedAssemblies.Add(assembly);
                    _logger.LogInformation("Loaded plugin assembly: {Name}", assembly.FullName);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to load plugin: {Path}", dllPath);
            }
        }
    }

    public async Task UploadPluginAsync(Stream stream, string filename)
    {
        // Security Warning: detailed validation of the assembly should happen here.
        // For now, we only allow .dll extension.
        if (!filename.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException("Only .dll files are allowed.");
        }

        // To avoid file locking issues on update, typically you might use versioned names 
        // or shadow copying. For this simple implementation, we assume new filenames.
        var filePath = Path.Combine(_pluginsPath, filename);

        // If file exists, we can't overwrite it while it's loaded in .NET Core (usually).
        // A simple strategy is to append a timestamp if it exists, or fail.
        if (File.Exists(filePath))
        {
             var nameWithoutExt = Path.GetFileNameWithoutExtension(filename);
             var ext = Path.GetExtension(filename);
             filename = $"{nameWithoutExt}_{DateTime.UtcNow.Ticks}{ext}";
             filePath = Path.Combine(_pluginsPath, filename);
        }

        using (var fileStream = new FileStream(filePath, FileMode.Create))
        {
            await stream.CopyToAsync(fileStream);
        }

        _logger.LogInformation("Plugin uploaded to {Path}", filePath);
        
        // Attempt to load immediately
        try
        {
            var assembly = Assembly.LoadFrom(filePath);
            _loadedAssemblies.Add(assembly);
            
            // Note: Components/Router might need a refresh to pick this up immediately.
            // In Blazor Server, the Router usually listens to state changes if wired up, 
            // but standard Router doesn't automatically watch a list. 
            // We might need to trigger a UI refresh or user might need to reload page.
            OnPluginLoaded?.Invoke(); 
        }
        catch (Exception ex)
        {
             _logger.LogError(ex, "Failed to load uploaded plugin immediately.");
             // Depending on needs, might delete the bad file here.
        }
    }
    
    public event Action? OnPluginLoaded;
}
