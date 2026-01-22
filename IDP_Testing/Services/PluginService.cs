using System.Reflection;
using System.Collections.Concurrent;

namespace IDP_Testing.Services;

public class PluginService
{
    private readonly string _pluginsPath;
    private readonly ILogger<PluginService> _logger;
    private readonly ConcurrentBag<Assembly> _loadedAssemblies = new();
    private readonly object _loadLock = new();

    public IReadOnlyList<Assembly> LoadedAssemblies => _loadedAssemblies.ToList().AsReadOnly();
    public event Action? OnPluginLoaded;

    public PluginService(IWebHostEnvironment env, ILogger<PluginService> logger)
    {
        _pluginsPath = Path.Combine(env.ContentRootPath, "Plugins");
        _logger = logger;
        
        // Ensure directory exists
        if (!Directory.Exists(_pluginsPath))
        {
            Directory.CreateDirectory(_pluginsPath);
        }
        
        _logger.LogInformation("PluginService initialized as singleton. Plugins path: {Path}", _pluginsPath);
    }

    public void LoadPlugins()
    {
        lock (_loadLock)
        {
            _logger.LogInformation("Loading plugins from {Path}", _pluginsPath);
            
            var dllFiles = Directory.GetFiles(_pluginsPath, "*.dll");
            _logger.LogInformation("Found {Count} DLL files in plugins directory", dllFiles.Length);
            
            foreach (var dllPath in dllFiles)
            {
                try
                {
                    var assembly = Assembly.LoadFrom(dllPath);
                    
                    if (!_loadedAssemblies.Contains(assembly))
                    {
                        _loadedAssemblies.Add(assembly);
                        _logger.LogInformation("Loaded plugin assembly: {Name} from {Path}", 
                            assembly.FullName, dllPath);
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Failed to load plugin from {Path}", dllPath);
                }
            }
            
            _logger.LogInformation("Total plugins loaded: {Count}", _loadedAssemblies.Count);
        }
    }

    public async Task UploadPluginAsync(Stream stream, string filename)
    {
        _logger.LogInformation("=== UploadPluginAsync START === File: {Filename}", filename);
        
        // Validate file extension
        if (!filename.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
        {
            _logger.LogWarning("Rejected non-DLL file: {Filename}", filename);
            throw new ArgumentException("Only .dll files are allowed.");
        }

        var filePath = Path.Combine(_pluginsPath, filename);
        _logger.LogInformation("Target path: {Path}", filePath);

        // Handle existing files by appending timestamp
        if (File.Exists(filePath))
        {
             var nameWithoutExt = Path.GetFileNameWithoutExtension(filename);
             var ext = Path.GetExtension(filename);
             filename = $"{nameWithoutExt}_{DateTime.UtcNow.Ticks}{ext}";
             filePath = Path.Combine(_pluginsPath, filename);
             _logger.LogInformation("File exists, renamed to: {Filename}", filename);
        }

        // Save the file
        try
        {
            _logger.LogInformation("Saving file to disk...");
            using (var fileStream = new FileStream(filePath, FileMode.Create))
            {
                await stream.CopyToAsync(fileStream);
            }
            _logger.LogInformation("File saved successfully");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to save file");
            throw new IOException($"Failed to save file: {ex.Message}", ex);
        }
        
        // Attempt to load the assembly immediately
        try
        {
            _logger.LogInformation("Loading assembly from: {Path}", filePath);
            
            lock (_loadLock)
            {
                var assembly = Assembly.LoadFrom(filePath);
                _loadedAssemblies.Add(assembly);
                
                _logger.LogInformation("Assembly loaded successfully: {Name}, Version: {Version}", 
                    assembly.GetName().Name, assembly.GetName().Version);
                
                // Notify all subscribers (NavMenu instances)
                OnPluginLoaded?.Invoke();
                _logger.LogInformation("=== UploadPluginAsync SUCCESS ===");
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to load assembly");
            
            // Delete the file if it can't be loaded
            try
            {
                File.Delete(filePath);
                _logger.LogInformation("Deleted invalid file: {Path}", filePath);
            }
            catch (Exception deleteEx)
            {
                _logger.LogError(deleteEx, "Failed to delete file");
            }
            
            // Re-throw the exception so the UI can display the error
            throw new InvalidOperationException($"Failed to load plugin: {ex.Message}", ex);
        }
    }
}
