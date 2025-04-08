using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Identity.Web;
using Microsoft.AspNetCore.Authentication;

var builder = WebApplication.CreateBuilder(args);

// Authentication with OpenID Connect and Role Claims
builder.Services.AddAuthentication(OpenIdConnectDefaults.AuthenticationScheme)
    .AddMicrosoftIdentityWebApp(builder.Configuration.GetSection("AzureAd"))
    .EnableTokenAcquisitionToCallDownstreamApi(new[] { "User.Read" })
    .AddInMemoryTokenCaches();

builder.Services.Configure<OpenIdConnectOptions>(OpenIdConnectDefaults.AuthenticationScheme, options =>
{
    options.TokenValidationParameters.RoleClaimType = "roles"; // Ensure roles are mapped correctly
});

// Configure cookie settings to handle unauthenticated users
builder.Services.ConfigureApplicationCookie(options =>
{
    options.LoginPath = "/signin"; // Redirect unauthenticated users to /signin
    options.AccessDeniedPath = "/Account/AccessDenied"; // Redirect unauthorized users to AccessDenied
});

// Register Identity services with Entity Framework
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection"),
    sqlOptions => sqlOptions.EnableRetryOnFailure()));

builder.Services.AddIdentity<IdentityUser, IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();

// Custom claims transformation
builder.Services.AddTransient<IClaimsTransformation, CustomRoleClaimsTransformer>();

// Add MVC Controllers with Views
builder.Services.AddControllersWithViews();

var app = builder.Build();

// Ensure roles and user assignment at startup
using (var scope = app.Services.CreateScope())
{
    var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
    var userManager = scope.ServiceProvider.GetRequiredService<UserManager<IdentityUser>>();

    // Define roles
    string adminRole = "Admin";
    string userRole = "USER"; // Define user role

    // Ensure the Admin role exists
    if (!await roleManager.RoleExistsAsync(adminRole))
    {
        await roleManager.CreateAsync(new IdentityRole(adminRole));
        Console.WriteLine($"Role '{adminRole}' has been created.");
    }

    // Ensure the User role exists
    if (!await roleManager.RoleExistsAsync(userRole))
    {
        await roleManager.CreateAsync(new IdentityRole(userRole));
        Console.WriteLine($"Role '{userRole}' has been created.");
    }

    // Define Admin user details
    string adminEmail = "stevenbyrne243@gmail.com"; // Replace with your desired admin email
    string adminPassword = "P@$$w0rd01"; // Replace with your desired admin password

    var adminUser = await userManager.FindByEmailAsync(adminEmail);
    if (adminUser == null)
    {
        adminUser = new IdentityUser
        {
            UserName = adminEmail,
            Email = adminEmail,
            EmailConfirmed = true
        };

        var createUserResult = await userManager.CreateAsync(adminUser, adminPassword);
        if (createUserResult.Succeeded)
        {
            Console.WriteLine($"Admin user '{adminEmail}' has been created.");
        }
        else
        {
            foreach (var error in createUserResult.Errors)
            {
                Console.WriteLine($"Error creating admin user: {error.Description}");
            }
        }
    }

    if (!await userManager.IsInRoleAsync(adminUser, adminRole))
    {
        await userManager.AddToRoleAsync(adminUser, adminRole);
        Console.WriteLine($"Admin user '{adminEmail}' has been assigned the '{adminRole}' role.");
    }

    // Define User details (optional: seed a default user)
    string userEmail = "defaultuser@example.com"; // Replace with your desired user email
    string userPassword = "User@123"; // Replace with your desired user password

    var user = await userManager.FindByEmailAsync(userEmail);
    if (user == null)
    {
        user = new IdentityUser
        {
            UserName = userEmail,
            Email = userEmail,
            EmailConfirmed = true
        };

        var createUserResult = await userManager.CreateAsync(user, userPassword);
        if (createUserResult.Succeeded)
        {
            Console.WriteLine($"User '{userEmail}' has been created.");
        }
        else
        {
            foreach (var error in createUserResult.Errors)
            {
                Console.WriteLine($"Error creating user: {error.Description}");
            }
        }
    }

    if (!await userManager.IsInRoleAsync(user, userRole))
    {
        await userManager.AddToRoleAsync(user, userRole);
        Console.WriteLine($"User '{userEmail}' has been assigned the '{userRole}' role.");
    }

    // Debug roles
    var fetchedAdminUser = await userManager.FindByEmailAsync(adminEmail);
    if (fetchedAdminUser != null)
    {
        var adminRoles = await userManager.GetRolesAsync(fetchedAdminUser);
        Console.WriteLine($"Admin user roles: {string.Join(", ", adminRoles)}");
    }

    var fetchedUser = await userManager.FindByEmailAsync(userEmail);
    if (fetchedUser != null)
    {
        var userRoles = await userManager.GetRolesAsync(fetchedUser);
        Console.WriteLine($"Default user roles: {string.Join(", ", userRoles)}");
    }
}

// Middleware pipeline
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
}

// HTTPS Redirection
app.UseHttpsRedirection();

// Static file serving
app.UseStaticFiles();

// Routing
app.UseRouting();

// Authentication and Authorization Middleware
app.UseAuthentication();
app.UseAuthorization();

// Route configuration: Set up routing for `/signin` and default routes
app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.MapControllerRoute(
    name: "signin",
    pattern: "signin",
    defaults: new { controller = "Account", action = "Login" });


app.Run();
