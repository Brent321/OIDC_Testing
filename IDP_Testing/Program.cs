using IDP_Testing.Components;
using IDP_Testing.Configuration;
using IDP_Testing.Data;
using IDP_Testing.Extensions;
using IDP_Testing.Services;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

// Get connection string for EF Core
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection")
    ?? throw new InvalidOperationException("Connection string 'DefaultConnection' not found.");

// Add EF Core Configuration Provider BEFORE other services
// This allows configuration values to be loaded from the database
builder.Configuration.AddEFCoreConfiguration(options =>
    options.UseSqlServer(connectionString));

builder.Services.AddCustomAuthentication(builder);
builder.Services.AddCustomAuthorization();
builder.Services.AddControllers();

// Add Blazor services
builder.Services.AddBlazorServices();

// Add DbContext for configuration storage
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(connectionString));

// Add Configuration Service for managing database configurations
builder.Services.AddScoped<IConfigurationService, ConfigurationService>();

// Add session services
builder.Services.AddDistributedMemoryCache();
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromHours(1);
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
    options.Cookie.SecurePolicy = builder.Environment.IsDevelopment() 
        ? CookieSecurePolicy.None 
        : CookieSecurePolicy.Always;
});

builder.Services.AddAntiforgery();

var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    app.UseHsts();
}

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

// Enable session middleware
app.UseSession();

app.UseCustomStatusCodePages();

app.UseAntiforgery();

app.MapControllers();

// Serve static files to support both Blazor and React assets
app.UseStaticFiles();

// Map React SPA fallback for the /react path
app.MapFallbackToFile("react/{**slug}", "react/index.html");

// Map Blazor components for the root application
app.MapStaticAssets();
app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

app.Run();
