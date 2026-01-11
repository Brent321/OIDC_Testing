using Microsoft.EntityFrameworkCore;
using IDP_Testing.Data;
using IDP_Testing.Services;
using IDP_Testing.Configuration;

var builder = WebApplication.CreateBuilder(args);

// Get connection string for EF Core
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection")
    ?? throw new InvalidOperationException("Connection string 'DefaultConnection' not found.");

// Add EF Core Configuration Provider BEFORE building configuration
builder.Configuration.AddEFCoreConfiguration(options =>
    options.UseSqlServer(connectionString));

// Add services to the container
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

builder.Services.AddControllers();

// Add DbContext
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(connectionString));

// Add Configuration Service
builder.Services.AddScoped<IConfigurationService, ConfigurationService>();

// Add Authentication & Authorization
builder.Services.AddAuthentication();
builder.Services.AddAuthorization();

var app = builder.Build();

// Configure the HTTP request pipeline
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseAntiforgery();

app.UseAuthentication();
app.UseAuthorization();

app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

app.MapControllers();

app.Run();