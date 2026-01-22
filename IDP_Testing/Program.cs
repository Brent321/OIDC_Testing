using IDP_Testing.Components;
using IDP_Testing.Configuration;
using IDP_Testing.Data;
using IDP_Testing.Extensions;
using IDP_Testing.Services;
using Microsoft.EntityFrameworkCore;
using System;

var builder = WebApplication.CreateBuilder(args);

// ==============================================================================
// 1. Configuration Setup
// ==============================================================================

// Retrieve the database connection string from appsettings.json
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection")
    ?? throw new InvalidOperationException("Connection string 'DefaultConnection' not found.");

// Register the custom EF Core Configuration Provider.
// This is critical to run BEFORE other services so that configuration values 
// (like Authentication settings) can be loaded from the database instead of just appsettings.json.
builder.Configuration.AddEFCoreConfiguration(options =>
    options.UseSqlServer(connectionString));

// ==============================================================================
// 2. Service Registration
// ==============================================================================

// Register Authentication services (OIDC, SAML, WS-Fed) based on configuration
builder.Services.AddCustomAuthentication(builder);

// Register Authorization policies
builder.Services.AddCustomAuthorization();

// Register Controllers for API and Authentication endpoints
builder.Services.AddControllers();

// Register Blazor specific services (Server-side rendering, interactive mode)
builder.Services.AddBlazorServices();

// Register the EF Core DbContext for the application
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(connectionString));

// Register the internal service for managing database-stored configurations
builder.Services.AddScoped<IConfigurationService, ConfigurationService>();

// Configure Session State
// This is used to store temporary authentication artifacts and user state.
builder.Services.AddDistributedMemoryCache();
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromHours(1);
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
    
    // In Development, we allow non-secure cookies to support http://localhost testing.
    // In Production, Always enforcement ensures cookies are only sent over HTTPS.
    options.Cookie.SecurePolicy = builder.Environment.IsDevelopment() 
        ? CookieSecurePolicy.None 
        : CookieSecurePolicy.Always;
});

// Register Antiforgery token services for form security
builder.Services.AddAntiforgery();

// Configure React Development Proxy (with YARP and Hot Reload)
builder.Services.AddReactDevelopmentProxy(builder.Environment, builder.Configuration);
var app = builder.Build();

// ==============================================================================
// 3. Request Pipeline Configuration (Middleware)
// ==============================================================================

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    // detailed error page in dev, generic error handler in prod
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    // The default HSTS value is 30 days. You may want to change this for production scenarios.
    app.UseHsts();
}

app.UseHttpsRedirection();

// Enable Authentication and Authorization capabilities
app.UseAuthentication();
app.UseAuthorization();

// Enable Session Middleware (must be after UseCookiePolicy if present, and before endpoints)
app.UseSession();

// Adds a status code page for HTTP errors (e.g. 404)
app.UseCustomStatusCodePages();

// Validate Antiforgery tokens
app.UseAntiforgery();

// ==============================================================================
// 4. Endpoint Routing
// ==============================================================================

// Map API and Authentication controllers
app.MapControllers();

// Serve static files (css, js, images) to support both Blazor and React assets
app.UseStaticFiles();

// In Development, proxy /react requests to the Vite Dev Server (if enabled)
if (app.Environment.IsDevelopment() && app.Configuration.GetValue<bool>("React:UseDevelopmentServer", true))
{
    app.MapReverseProxy();
}

// REACT FRONTEND SUPPORT (Production Fallback):
// Map the React SPA fallback for any requests starting with /react
// If a request matches /react/... and isn't a file, serve index.html
app.MapFallbackToFile("react/{**slug}", "react/index.html");

// BLAZOR FRONTEND SUPPORT:
// Map static assets for Blazor (e.g. _framework/blazor.web.js)
app.MapStaticAssets();
// Map the root Blazor App component to the root URL "/"
app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

app.Run();
