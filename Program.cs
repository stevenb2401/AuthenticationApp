using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Identity.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using AuthenticationApp.Data;
using AuthenticationApp.Models;
using AuthenticationApp.Services;

var builder = WebApplication.CreateBuilder(args);

// DEBUG: Check configuration loading
Console.WriteLine("=== Configuration Debug ===");
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");
Console.WriteLine($"Connection string found: {!string.IsNullOrEmpty(connectionString)}");
Console.WriteLine($"Connection string: {connectionString}");
Console.WriteLine("=== End Debug ===");

// Register DbContext with connection string
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
})
.AddEntityFrameworkStores<ApplicationDbContext>()
.AddDefaultTokenProviders();

// Authentication with OpenID Connect
builder.Services.AddAuthentication(OpenIdConnectDefaults.AuthenticationScheme)
    .AddMicrosoftIdentityWebApp(builder.Configuration.GetSection("AzureAd"))
    .EnableTokenAcquisitionToCallDownstreamApi(new[] { "User.Read" })
    .AddInMemoryTokenCaches();

builder.Services.Configure<OpenIdConnectOptions>(OpenIdConnectDefaults.AuthenticationScheme, options =>
{
    options.TokenValidationParameters.RoleClaimType = "roles";
});

// Configure cookie settings
builder.Services.ConfigureApplicationCookie(options =>
{
    options.LoginPath = "/signin";
    options.AccessDeniedPath = "/Account/AccessDenied";
});

// REGISTER AUTHORIZATION HANDLERS for Task 2A
builder.Services.AddScoped<IAuthorizationHandler, RoleAuthorizationHandler>();
builder.Services.AddScoped<IAuthorizationHandler, TenantAuthorizationHandler>();
builder.Services.AddScoped<IAuthorizationHandler, ClaimAuthorizationHandler>();
builder.Services.AddScoped<IAuthorizationHandler, DepartmentAuthorizationHandler>();
builder.Services.AddScoped<IAuthorizationHandler, BusinessHoursAuthorizationHandler>();

// CONFIGURE AUTHORIZATION POLICIES for Task 2A
builder.Services.AddAuthorization(options =>
{
    // Default policy requires authentication
    options.FallbackPolicy = options.DefaultPolicy;

    // ROLE-BASED POLICIES
    options.AddPolicy("AdminOnly", policy =>
        policy.AddRequirements(new RoleRequirement(new[] { "Admin", "Administrator", "Global Administrator" })));

    options.AddPolicy("ManagerOrAdmin", policy =>
        policy.AddRequirements(new RoleRequirement(new[] { "Manager", "Admin", "Administrator" })));

    options.AddPolicy("HR_Access", policy =>
        policy.AddRequirements(new RoleRequirement(new[] { "HR", "Human Resources", "HR Manager" })));

    // DEPARTMENT-BASED POLICIES
    options.AddPolicy("IT_Department", policy =>
        policy.AddRequirements(new DepartmentRequirement("IT", "Information Technology", "Technical")));

    options.AddPolicy("Finance_Department", policy =>
        policy.AddRequirements(new DepartmentRequirement("Finance", "Accounting", "Financial")));

    // BUSINESS HOURS POLICY
    options.AddPolicy("BusinessHours", policy =>
        policy.AddRequirements(new BusinessHoursRequirement(
            new TimeSpan(9, 0, 0),  // 9:00 AM
            new TimeSpan(17, 0, 0), // 5:00 PM
            DayOfWeek.Monday, DayOfWeek.Tuesday, DayOfWeek.Wednesday, DayOfWeek.Thursday, DayOfWeek.Friday)));

    // COMBINED POLICIES
    options.AddPolicy("AdminBusinessHours", policy =>
    {
        policy.AddRequirements(new RoleRequirement(new[] { "Admin", "Administrator" }));
        policy.AddRequirements(new BusinessHoursRequirement(
            new TimeSpan(8, 0, 0),
            new TimeSpan(18, 0, 0),
            DayOfWeek.Monday, DayOfWeek.Tuesday, DayOfWeek.Wednesday, DayOfWeek.Thursday, DayOfWeek.Friday));
    });

    // CLAIM-BASED POLICIES
    options.AddPolicy("VerifiedUsers", policy =>
        policy.AddRequirements(new ClaimRequirement("email_verified", "true")));

    // TENANT-SPECIFIC POLICY
    var tenantId = builder.Configuration["AzureAd:TenantId"] ?? "your-tenant-id-here";
    options.AddPolicy("SpecificTenant", policy =>
        policy.AddRequirements(new TenantRequirement(tenantId)));

    // ADDITIONAL POLICIES for your existing Identity setup
    options.AddPolicy("LocalAdminOnly", policy =>
        policy.RequireRole("Admin")); // Uses ASP.NET Identity roles

    options.AddPolicy("LocalUserOnly", policy =>
        policy.RequireRole("USER", "Admin")); // Uses ASP.NET Identity roles
});

// Add MVC Controllers with Views
builder.Services.AddControllersWithViews();

// Add logging for debugging authorization
builder.Services.AddLogging(logging =>
{
    logging.AddConsole();
    logging.AddDebug();
    if (builder.Environment.IsDevelopment())
    {
        logging.SetMinimumLevel(LogLevel.Debug);
    }
});

var app = builder.Build();

// Create database and seed roles
using (var scope = app.Services.CreateScope())
{
    var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
    var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
    var userManager = scope.ServiceProvider.GetRequiredService<UserManager<IdentityUser>>();

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

    // Create roles - Enhanced for Task 2A
    string[] roles = { "Admin", "USER", "Manager", "HR", "HR Manager" };
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
else
{
    // DEBUGGING: Add route debugging in development for Task 2A
    app.MapGet("/debug/routes", (LinkGenerator linkGenerator) => 
    {
        var routes = new List<string>
        {
            linkGenerator.GetPathByAction("Index", "AuthorizationTest"),
            linkGenerator.GetPathByAction("AdminOnly", "AuthorizationTest"),
            linkGenerator.GetPathByAction("Details", "Profile"),
            linkGenerator.GetPathByAction("Index", "Home")
        };
        return Results.Json(routes);
    });

    // Debug authorization policies
    app.MapGet("/debug/policies", (IAuthorizationPolicyProvider policyProvider) =>
    {
        var policies = new[]
        {
            "AdminOnly", "ManagerOrAdmin", "HR_Access", "IT_Department", 
            "Finance_Department", "BusinessHours", "AdminBusinessHours", 
            "VerifiedUsers", "LocalAdminOnly", "LocalUserOnly"
        };
        return Results.Json(policies);
    });
}

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

// ENHANCED ROUTING for Task 2A
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

Console.WriteLine("=== Authorization Policies Configured ===");
Console.WriteLine("Available policies: AdminOnly, ManagerOrAdmin, HR_Access, IT_Department, Finance_Department, BusinessHours, AdminBusinessHours, VerifiedUsers");
Console.WriteLine("Test URL: /AuthorizationTest");
Console.WriteLine("Debug URLs: /debug/routes, /debug/policies");
Console.WriteLine("=== End Authorization Debug ===");

app.Run();