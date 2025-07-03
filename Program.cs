using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Identity.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using AuthenticationApp.Data;
using AuthenticationApp.Models;
using AuthenticationApp.Services;
using Microsoft.ApplicationInsights.Extensibility;
using Azure.Identity;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);

// Add Application Insights for Azure monitoring
builder.Services.AddApplicationInsightsTelemetry(builder.Configuration["ApplicationInsights:ConnectionString"]);

// Configure Application Insights with Azure credentials
builder.Services.Configure<TelemetryConfiguration>(telemetryConfiguration =>
{
    // Use DefaultAzureCredential for authentication to Azure
    telemetryConfiguration.SetAzureTokenCredential(new DefaultAzureCredential());
});

// Add HTTP Context Accessor for telemetry
builder.Services.AddHttpContextAccessor();

// Add custom telemetry services
builder.Services.AddSingleton<ITelemetryInitializer, UserTelemetryInitializer>();
builder.Services.AddScoped<IUserActivityService, UserActivityService>();

// Register DbContext with connection string
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(connectionString ?? throw new InvalidOperationException("Connection string 'DefaultConnection' not found."),
    sqlOptions => sqlOptions.EnableRetryOnFailure()));

// Register Identity services
builder.Services.AddIdentity<IdentityUser, IdentityRole>(options =>
{
    // Password settings
    options.Password.RequireDigit = true;
    options.Password.RequiredLength = 8;
    options.Password.RequireNonAlphanumeric = false;
    options.Password.RequireUppercase = true;
    options.Password.RequireLowercase = true;
    
    // Lockout settings for security monitoring
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
    options.Lockout.MaxFailedAccessAttempts = 5;
    options.Lockout.AllowedForNewUsers = true;
    
    // User settings
    options.User.RequireUniqueEmail = true;
    options.SignIn.RequireConfirmedEmail = false; // Set to true in production
})
.AddEntityFrameworkStores<ApplicationDbContext>()
.AddDefaultTokenProviders();

// Authentication with OpenID Connect
builder.Services.AddAuthentication(OpenIdConnectDefaults.AuthenticationScheme)
    .AddMicrosoftIdentityWebApp(builder.Configuration.GetSection("AzureAd"))
    .EnableTokenAcquisitionToCallDownstreamApi(new[] { 
        "User.Read", 
        "Directory.Read.All", 
        "AuditLog.Read.All" 
    })
    .AddInMemoryTokenCaches();

builder.Services.Configure<OpenIdConnectOptions>(OpenIdConnectDefaults.AuthenticationScheme, options =>
{
    options.TokenValidationParameters.RoleClaimType = "roles";
    
    // Add custom event handlers for monitoring
    options.Events = new OpenIdConnectEvents
    {
        OnTokenValidated = async context =>
        {
            var userActivityService = context.HttpContext.RequestServices.GetRequiredService<IUserActivityService>();
            var userId = context.Principal?.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            var email = context.Principal?.FindFirst(ClaimTypes.Email)?.Value;
            
            if (!string.IsNullOrEmpty(userId))
            {
                userActivityService.TrackUserLogin(userId, email ?? "Unknown", "AzureAD", true);
            }
        },
        OnAuthenticationFailed = async context =>
        {
            var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
            logger.LogWarning("Azure AD authentication failed: {Error}", context.Exception?.Message);
        }
    };
});

// Configure cookie settings
builder.Services.ConfigureApplicationCookie(options =>
{
    options.LoginPath = "/signin";
    options.AccessDeniedPath = "/Account/AccessDenied";
    options.ExpireTimeSpan = TimeSpan.FromMinutes(60);
    options.SlidingExpiration = true;
    
    // Add cookie events for session monitoring
    options.Events.OnSignedIn = async context =>
    {
        var userActivityService = context.HttpContext.RequestServices.GetRequiredService<IUserActivityService>();
        var userId = context.Principal?.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        var email = context.Principal?.FindFirst(ClaimTypes.Email)?.Value;
        
        if (!string.IsNullOrEmpty(userId))
        {
            userActivityService.TrackUserLogin(userId, email ?? "Unknown", "Local", true);
        }
    };
});

// REGISTER ONLY USED AUTHORIZATION HANDLERS
builder.Services.AddScoped<IAuthorizationHandler, RoleAuthorizationHandler>();

// Configure Authorization Policies
builder.Services.AddAuthorization(options =>
{
    // Default policy requires authentication
    options.FallbackPolicy = options.DefaultPolicy;

    // ROLE-BASED POLICIES 
    options.AddPolicy("Admin", policy =>
        policy.AddRequirements(new RoleRequirement(new[] { "Admin", "Administrator", "Global Administrator" })));

    options.AddPolicy("Manager_or_Admin", policy =>
        policy.AddRequirements(new RoleRequirement(new[] { "Manager", "Admin", "Administrator" })));

    options.AddPolicy("HR_Access", policy =>
        policy.AddRequirements(new RoleRequirement(new[] { "HR", "Human Resources", "HR Manager" })));

    // LOCAL IDENTITY POLICIES
    options.AddPolicy("Local_Admin", policy =>
        policy.RequireRole("Admin")); 

    options.AddPolicy("Local_User", policy =>
        policy.RequireRole("User", "Admin")); 
});

// Add MVC Controllers with Views
builder.Services.AddControllersWithViews();

// Enhanced logging with Application Insights
builder.Services.AddLogging(logging =>
{
    logging.AddConsole();
    logging.AddDebug();
    logging.AddApplicationInsights();
    
    if (builder.Environment.IsDevelopment())
    {
        logging.SetMinimumLevel(LogLevel.Debug);
    }
    else
    {
        logging.SetMinimumLevel(LogLevel.Information);
    }
});

var app = builder.Build();

// Create database and seed roles with monitoring
using (var scope = app.Services.CreateScope())
{
    var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
    var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
    var userManager = scope.ServiceProvider.GetRequiredService<UserManager<IdentityUser>>();
    var userActivityService = scope.ServiceProvider.GetRequiredService<IUserActivityService>();

    // Ensure database is created
    try
    {
        context.Database.EnsureCreated();
        Console.WriteLine("Database created/verified successfully.");
    }
    catch (Exception ex)
    {
        Console.WriteLine($"Database creation error: {ex.Message}");
    }

    // Create roles
    string[] roles = { "Admin", "User", "Manager", "HR", "HR Manager" };
    foreach (var role in roles)
    {
        if (!await roleManager.RoleExistsAsync(role))
        {
            await roleManager.CreateAsync(new IdentityRole(role));
            Console.WriteLine($"Role '{role}' created.");
        }
    }

    // Create admin user
    string adminEmail = "stevenbyrne243@gmail.com";
    string adminPassword = "P@$$w0rd01";

    var adminUser = await userManager.FindByEmailAsync(adminEmail);
    if (adminUser == null)
    {
        adminUser = new IdentityUser
        {
            UserName = adminEmail,
            Email = adminEmail,
            EmailConfirmed = true
        };

        var result = await userManager.CreateAsync(adminUser, adminPassword);
        if (result.Succeeded)
        {
            await userManager.AddToRoleAsync(adminUser, "Admin");
            Console.WriteLine($"Admin user created and assigned Admin role.");
            
            // Track admin user creation
            userActivityService.TrackUserAction(adminUser.Id, "AdminUserCreated", new Dictionary<string, string>
            {
                ["Email"] = adminEmail,
                ["CreatedBy"] = "System",
                ["Timestamp"] = DateTime.UtcNow.ToString()
            });
        }
        else
        {
            Console.WriteLine($"Error creating admin user: {string.Join(", ", result.Errors.Select(e => e.Description))}");
        }
    }
}

// Middleware pipeline
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

// ROUTING
app.MapControllerRoute(
    name: "authorisation_test",
    pattern: "AuthorisationTest/{action=Index}",
    defaults: new { controller = "AuthorisationTest" });

app.MapControllerRoute(
    name: "admin",
    pattern: "Admin/{action=Index}",
    defaults: new { controller = "Admin" });

app.MapControllerRoute(
    name: "profile_default",
    pattern: "Profile",
    defaults: new { controller = "Profile", action = "Index" });

app.MapControllerRoute(
    name: "profile",
    pattern: "Profile/{action=Index}",
    defaults: new { controller = "Profile" });

app.MapControllerRoute(
    name: "signin",
    pattern: "signin",
    defaults: new { controller = "Account", action = "Login" });

// DEFAULT ROUTE MUST BE LAST
app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");  

app.Run();