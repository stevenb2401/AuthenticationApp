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
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;

var builder = WebApplication.CreateBuilder(args);

// Confiuration Validation
var requiredSettings = new[]
{
    "AzureAd:Instance",
    "AzureAd:TenantId", 
    "AzureAd:ClientId",
    "AzureAd:ClientSecret",
    "ConnectionStrings:DefaultConnection"
};

foreach (var setting in requiredSettings)
{
    if (string.IsNullOrEmpty(builder.Configuration[setting]))
    {
        throw new InvalidOperationException($"Required configuration '{setting}' is missing.");
    }
}

// Data Protection Configuration
builder.Services.AddDataProtection()
    .SetApplicationName("AuthenticationApp")
    .PersistKeysToFileSystem(new DirectoryInfo(Path.Combine(
        builder.Environment.ContentRootPath, "DataProtection-Keys")))
    .SetDefaultKeyLifetime(TimeSpan.FromDays(90))
    .DisableAutomaticKeyGeneration();

// Antiforgery Configuration
builder.Services.AddAntiforgery(options =>
{
    options.Cookie.SameSite = SameSiteMode.None;
    options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
});

// Application Insights Configuration for Azure
builder.Services.AddApplicationInsightsTelemetry(options =>
{
    options.ConnectionString = "your-connection-string";
});

builder.Services.Configure<TelemetryConfiguration>(telemetryConfiguration =>
{
    telemetryConfiguration.SetAzureTokenCredential(new DefaultAzureCredential());
});

// HttpContext Accessor
builder.Services.AddHttpContextAccessor();

// Telemetry Initialiser
builder.Services.AddSingleton<ITelemetryInitializer, UserTelemetryInitializer>();
builder.Services.AddScoped<IUserActivityService, UserActivityService>();

// Register DbContext with connection string
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(connectionString ?? throw new InvalidOperationException("Connection string 'DefaultConnection' not found."),
    sqlOptions => sqlOptions.EnableRetryOnFailure()));

// Identity Services Configuration
builder.Services.AddIdentity<IdentityUser, IdentityRole>(options =>
{
    // Password Policy
    options.Password.RequireDigit = true;
    options.Password.RequiredLength = 12; 
    options.Password.RequireNonAlphanumeric = true; 
    options.Password.RequireUppercase = true;
    options.Password.RequireLowercase = true;
    options.Password.RequiredUniqueChars = 6; 
    
    // Lockout Settings
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15); 
    options.Lockout.MaxFailedAccessAttempts = 3;
    options.Lockout.AllowedForNewUsers = true;
    
    // User Settings
    options.User.RequireUniqueEmail = true;
    
    // Environment-specific email confirmation
    if (builder.Environment.IsProduction())
    {
        options.SignIn.RequireConfirmedEmail = true; 
    }
    else
    {
        options.SignIn.RequireConfirmedEmail = false;
    }
})
.AddEntityFrameworkStores<ApplicationDbContext>()
.AddDefaultTokenProviders();

// Cookie Authentication Configuration
builder.Services.ConfigureApplicationCookie(options =>
{
    options.LoginPath = "/Account/Login";
    options.AccessDeniedPath = "/Account/AccessDenied";
    options.ExpireTimeSpan = TimeSpan.FromMinutes(60);
    options.SlidingExpiration = true;
    
    // Cookie Settings
    options.Cookie.HttpOnly = true;
    options.Cookie.Name = "AuthApp.Auth";
    options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
    options.Cookie.SameSite = SameSiteMode.None;
    
    options.Events.OnValidatePrincipal = async context =>
    {
        var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
        
        try
        {
            if (context.Principal?.Identity?.IsAuthenticated == true)
            {
                logger.LogInformation("Cookie validation successful for user: {User}", 
                    context.Principal.Identity.Name);
            }
            else
            {
                logger.LogWarning("Cookie validation failed - rejecting principal");
                context.RejectPrincipal();
            }
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error during cookie validation");
            context.RejectPrincipal();
        }
        
        await Task.CompletedTask;
    };
    
    options.Events.OnSigningIn = context =>
    {
        var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
        logger.LogInformation("Cookie signing in for user: {User}", 
            context.Principal?.Identity?.Name ?? "Unknown");
        return Task.CompletedTask;
    };
    
    options.Events.OnSigningOut = context =>
    {
        var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
        logger.LogInformation("Cookie signing out for user: {User}", 
            context.HttpContext.User?.Identity?.Name ?? "Unknown");
        return Task.CompletedTask;
    };
});

// Authentication Configuration
builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = IdentityConstants.ApplicationScheme;
    options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
    options.DefaultSignInScheme = IdentityConstants.ApplicationScheme;
})

// OpenID Connect Configuration

.AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, options =>
{
    // Load Azure AD settings from configuration
    var azureAdSection = builder.Configuration.GetSection("AzureAd");
    var instance = azureAdSection["Instance"];
    var tenantId = azureAdSection["TenantId"];
    var clientId = azureAdSection["ClientId"];
    var clientSecret = azureAdSection["ClientSecret"];
    
    // Basic OpenID Connect settings
    options.Authority = $"{instance.TrimEnd('/')}/{tenantId}/v2.0";
    options.ClientId = clientId;
    options.ClientSecret = clientSecret;
    options.CallbackPath = "/signin-oidc";
    options.SignedOutCallbackPath = "/signout-oidc";
    options.SignInScheme = IdentityConstants.ApplicationScheme;
    options.ResponseType = "code";
    options.SaveTokens = true;
    options.GetClaimsFromUserInfoEndpoint = true;
    options.UsePkce = true;
    
    // Configure OpenID Connect options
    options.ProtocolValidator.RequireStateValidation = false;
    options.ProtocolValidator.RequireNonce = false;
    options.RequireHttpsMetadata = false;
    
    options.CorrelationCookie.SameSite = SameSiteMode.None;
    options.CorrelationCookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
    options.CorrelationCookie.HttpOnly = false; 
    options.CorrelationCookie.IsEssential = true;
    options.CorrelationCookie.Path = "/";
    options.CorrelationCookie.Domain = null;
    options.CorrelationCookie.Name = "AzureAD.Correlation"; 
    
    options.NonceCookie.SameSite = SameSiteMode.None;
    options.NonceCookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
    options.NonceCookie.HttpOnly = false;
    options.NonceCookie.IsEssential = true;
    options.NonceCookie.Path = "/";
    options.NonceCookie.Domain = null;
    options.NonceCookie.Name = "AzureAD.Nonce"; 
    
    // Configure scopes
    options.Scope.Clear();
    options.Scope.Add("openid");
    options.Scope.Add("profile");
    options.Scope.Add("email");
    options.Scope.Add("User.Read");
    
    // Configure token validation
    options.TokenValidationParameters.RoleClaimType = "roles";
    options.TokenValidationParameters.NameClaimType = "name";
    options.TokenValidationParameters.ValidateIssuer = false; 
    options.TokenValidationParameters.ClockSkew = TimeSpan.FromMinutes(5);
    
    // Event Handlers for OpenID Connect
    options.Events = new OpenIdConnectEvents
    {
        OnRedirectToIdentityProvider = context =>
        {
            var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
            logger.LogInformation("Redirecting to Azure AD: {AuthorityUrl}", context.Options.Authority);
            logger.LogInformation("Client ID: {ClientId}", context.Options.ClientId);
            logger.LogInformation("Callback Path: {CallbackPath}", context.Options.CallbackPath);
            
            context.HttpContext.Response.Cookies.Delete("AzureAD.Correlation");
            context.HttpContext.Response.Cookies.Delete("AzureAD.Nonce");
            
            return Task.CompletedTask;
        },
        
        OnMessageReceived = context =>
        {
            var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
            logger.LogInformation("Message received from Azure AD");
            
            // Log Azure AD correlation cookies
            var correlationCookies = context.Request.Cookies.Where(c => c.Key.Contains("Correlation")).ToList();
            logger.LogInformation("Correlation cookies found: {Count}", correlationCookies.Count);
            foreach (var cookie in correlationCookies)
            {
                var cookieValue = cookie.Value ?? "";
                var displayValue = cookieValue.Length > 20 ? cookieValue.Substring(0, 20) : cookieValue;
                logger.LogInformation("Cookie: {Name} = {Value}", cookie.Key, displayValue);
            }
            
            return Task.CompletedTask;
        },
        
        OnTokenValidated = async context =>
        {
            var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
            var userManager = context.HttpContext.RequestServices.GetRequiredService<UserManager<IdentityUser>>();
            
            logger.LogInformation("Azure AD token validated successfully");
            
            try
            {
                // Get user information from Azure AD claims
                var email = context.Principal?.FindFirst(ClaimTypes.Email)?.Value ??
                           context.Principal?.FindFirst("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress")?.Value;
                var name = context.Principal?.FindFirst(ClaimTypes.Name)?.Value ?? 
                          context.Principal?.FindFirst("name")?.Value;
                var objectId = context.Principal?.FindFirst("oid")?.Value ?? 
                              context.Principal?.FindFirst("http://schemas.microsoft.com/identity/claims/objectidentifier")?.Value;
                
                logger.LogInformation("User email: {Email}, Name: {Name}, ObjectId: {ObjectId}", email, name, objectId);
                
                if (!string.IsNullOrEmpty(email))
                {
                    var existingUser = await userManager.FindByEmailAsync(email);
                    
                    if (existingUser == null)
                    {
                        var newUser = new IdentityUser
                        {
                            UserName = email,
                            Email = email,
                            EmailConfirmed = true,
                            PhoneNumber = objectId
                        };
                        
                        var result = await userManager.CreateAsync(newUser);
                        
                        if (result.Succeeded)
                        {
                            logger.LogInformation("Created new local user for Azure AD account: {Email}", email);
                            
                            if (email == "stevenbyrne243@gmail.com")
                            {
                                await userManager.AddToRoleAsync(newUser, "Admin");
                                logger.LogInformation("Added Admin role for {Email}", email);
                            }
                            else
                            {
                                await userManager.AddToRoleAsync(newUser, "User");
                                logger.LogInformation("Added User role for {Email}", email);
                            }
                            
                            existingUser = newUser;
                        }
                        else
                        {
                            logger.LogError("Failed to create user for {Email}: {Errors}", 
                                email, string.Join(", ", result.Errors.Select(e => e.Description)));
                            throw new InvalidOperationException($"Failed to create user: {string.Join(", ", result.Errors.Select(e => e.Description))}");
                        }
                    }
                    else
                    {
                        logger.LogInformation("Found existing local user for Azure AD account: {Email}", email);
                    }

                    // Add role claims
                    var identity = context.Principal.Identity as ClaimsIdentity;
                    if (identity != null && existingUser != null)
                    {
                        var existingRoleClaims = identity.FindAll(ClaimTypes.Role).ToList();
                        foreach (var claim in existingRoleClaims)
                        {
                            identity.RemoveClaim(claim);
                        }

                        var userRoles = await userManager.GetRolesAsync(existingUser);
                        foreach (var role in userRoles)
                        {
                            identity.AddClaim(new Claim(ClaimTypes.Role, role));
                        }

                        identity.AddClaim(new Claim("LocalUserId", existingUser.Id));

                        logger.LogInformation("Added local roles for {Email}: {Roles}", email, string.Join(", ", userRoles));
                    }
                }
                
                logger.LogInformation("Authentication completed successfully for {Email}", email);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Error during token validation for user processing");
                throw;
            }
        },
        
        OnAuthenticationFailed = context =>
        {
            var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
            logger.LogError(context.Exception, "Azure AD authentication failed: {Error}", context.Exception?.Message);
            
            // Clear problematic cookies
            context.HttpContext.Response.Cookies.Delete("AzureAD.Correlation");
            context.HttpContext.Response.Cookies.Delete("AzureAD.Nonce");
            context.HttpContext.Response.Cookies.Delete(".AspNetCore.OpenIdConnect.Nonce.CookieAuth");
            context.HttpContext.Response.Cookies.Delete(".AspNetCore.Correlation.OpenIdConnect");
            
            context.HandleResponse();
            context.Response.Redirect("/?error=auth_failed&details=" + Uri.EscapeDataString(context.Exception?.Message ?? "Unknown error"));
            return Task.CompletedTask;
        },
        
        OnRemoteFailure = context =>
        {
            var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
            logger.LogError("Azure AD remote failure: {Error}", context.Failure?.Message);
            
            // Clear all authentication cookies
            var cookiesToClear = new[]
            {
                "AzureAD.Correlation",
                "AzureAD.Nonce",
                ".AspNetCore.OpenIdConnect.Nonce.CookieAuth",
                ".AspNetCore.Correlation.OpenIdConnect",
                "AuthApp.Auth",
                ".AspNetCore.Identity.Application"
            };
            
            foreach (var cookie in cookiesToClear)
            {
                context.HttpContext.Response.Cookies.Delete(cookie);
            }
            
            context.HandleResponse();
            context.Response.Redirect("/?error=azure_auth_failed&details=" + Uri.EscapeDataString(context.Failure?.Message ?? "Unknown error"));
            return Task.CompletedTask;
        }
    };
});

// Authorisation Handlers
builder.Services.AddScoped<IAuthorizationHandler, RoleAuthorizationHandler>();

// Authorisation Policies
builder.Services.AddAuthorization(options =>
{
    // Role-Based Policies
    options.AddPolicy("RequireAdminRole", policy =>
        policy.RequireRole("Admin", "Administrator", "Global Administrator"));

    options.AddPolicy("RequireManagerOrAdmin", policy =>
        policy.RequireRole("Manager", "Admin", "Administrator"));

    options.AddPolicy("RequireHRAccess", policy =>
        policy.RequireRole("HR", "Human Resources", "HR Manager"));

    options.AddPolicy("RequireLocalAdmin", policy =>
        policy.RequireRole("Admin")); 

    options.AddPolicy("RequireLocalUser", policy =>
        policy.RequireRole("User", "Admin"));

    options.AddPolicy("Admin", policy =>
        policy.RequireRole("Admin", "Administrator", "Global Administrator"));

    options.AddPolicy("Manager_or_Admin", policy =>
        policy.RequireRole("Manager", "Admin", "Administrator"));

    options.AddPolicy("HR_Access", policy =>
        policy.RequireRole("HR", "Human Resources", "HR Manager"));

    options.AddPolicy("Local_Admin", policy =>
        policy.RequireRole("Admin"));

    options.AddPolicy("Local_User", policy =>
        policy.RequireRole("User", "Admin"));
        
    options.AddPolicy("RequireAnyAdmin", policy =>
        policy.RequireAssertion(context =>
            context.User.IsInRole("Admin") || 
            context.User.IsInRole("Administrator") ||
            context.User.IsInRole("Global Administrator")));
});

// MVC Controllers with Views
builder.Services.AddControllersWithViews();

// Logging Configuration
builder.Services.AddLogging(logging =>
{
    logging.ClearProviders(); 
    logging.AddConsole();
    logging.AddDebug();
    
    if (!builder.Environment.IsDevelopment())
    {
        logging.AddApplicationInsights();
    }
    
    // Set specific log levels for different namespaces
    logging.AddFilter("Microsoft.AspNetCore.Authentication", LogLevel.Trace);
    logging.AddFilter("Microsoft.AspNetCore.Authentication.OpenIdConnect", LogLevel.Trace);
    logging.AddFilter("Microsoft.AspNetCore.Authentication.Cookies", LogLevel.Trace);
    logging.AddFilter("Microsoft.AspNetCore.Authorization", LogLevel.Information);
    
    if (builder.Environment.IsDevelopment())
    {
        logging.SetMinimumLevel(LogLevel.Trace); 
    }
    else
    {
        logging.SetMinimumLevel(LogLevel.Information);
    }
});

var app = builder.Build();

// Database Initialisation
await InitializeDatabaseAsync(app.Services);

// Middleware Configuration
if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
}
else
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
    
    app.Use(async (context, next) =>
    {
        context.Response.Headers["X-Frame-Options"] = "DENY";
        context.Response.Headers["X-Content-Type-Options"] = "nosniff";
        context.Response.Headers["Referrer-Policy"] = "strict-origin-when-cross-origin";
        context.Response.Headers["X-XSS-Protection"] = "1; mode=block";
        context.Response.Headers["Content-Security-Policy"] = 
            "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;";
        
        await next();
    });
}

app.UseHttpsRedirection();
app.UseStaticFiles();

// Custom Middleware for Authentication Error Handling
app.Use(async (context, next) =>
{
    var logger = context.RequestServices.GetRequiredService<ILogger<Program>>();

    if (context.Request.Query.ContainsKey("error") &&
        (context.Request.Query["error"] == "auth_failed" || context.Request.Query["error"] == "azure_auth_failed"))
    {
        logger.LogInformation("Clearing authentication cookies due to error");

        // Clear ALL possible authentication cookies
        var cookiesToClear = new[]
        {
            "AzureAD.Correlation",
            "AzureAD.Nonce",
            ".AspNetCore.OpenIdConnect.Nonce.CookieAuth",
            ".AspNetCore.OpenIdConnect.Nonce.OpenIdConnect",
            ".AspNetCore.Correlation.OpenIdConnect",
            ".AspNetCore.Correlation.CookieAuth",
            "AuthApp.Auth",
            ".AspNetCore.Identity.Application",
            ".AspNetCore.Antiforgery"
        };

        foreach (var cookie in cookiesToClear)
        {
            if (context.Request.Cookies.ContainsKey(cookie))
            {
                logger.LogInformation("Deleting cookie: {Cookie}", cookie);
                context.Response.Cookies.Delete(cookie, new CookieOptions
                {
                    Path = "/",
                    Domain = null,
                    SameSite = SameSiteMode.None,
                    Secure = false
                });
            }
        }

        // Redirect to clean URL
        if (context.Request.Path == "/" && context.Request.Query.Count > 0)
        {
            context.Response.Redirect("/");
            return;
        }
    }

    // Callback Processing
    if (context.Request.Path == "/signin-oidc" && context.Request.Method == "POST")
    {
        logger.LogInformation("Processing Azure AD callback");

        var hasCorrelationCookie = context.Request.Cookies.Keys
            .Any(k => k.Contains("Correlation"));

        if (!hasCorrelationCookie)
        {
            logger.LogWarning("No correlation cookie found for callback - this might cause correlation failure");
        }
    }

    await next();
});

app.Use(async (context, next) =>
{
    var logger = context.RequestServices.GetRequiredService<ILogger<Program>>();
    logger.LogInformation("Request: {Method} {Path}, IsAuthenticated: {IsAuth}, User: {User}, Claims: {Claims}", 
        context.Request.Method,
        context.Request.Path,
        context.User?.Identity?.IsAuthenticated ?? false,
        context.User?.Identity?.Name ?? "Anonymous",
        context.User?.Identity?.IsAuthenticated == true 
            ? string.Join(", ", context.User.Claims.Select(c => $"{c.Type}:{c.Value}"))
            : "No claims");
    
    await next();
});

app.UseRouting();

app.UseAuthentication();

// Custom Middleware for Authentication Error Handling
app.Use(async (context, next) =>
{
    var logger = context.RequestServices.GetRequiredService<ILogger<Program>>();
    
    if (context.Request.Path.StartsWithSegments("/signin-oidc"))
    {
        logger.LogInformation("/signin-oidc request AFTER auth middleware: {Method} {Path}", 
            context.Request.Method, context.Request.Path);
        logger.LogInformation("Authentication result: {IsAuth}", context.User?.Identity?.IsAuthenticated);
        
        if (context.Request.Method == "POST" && context.User?.Identity?.IsAuthenticated != true)
        {
            logger.LogWarning("POST to /signin-oidc but still not authenticated");
        }
    }
    
    await next();
});

app.UseAuthorization();

// Route Configuration
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

app.MapControllerRoute(
    name: "azure_signin",
    pattern: "signin-azure",
    defaults: new { controller = "Account", action = "ExternalLogin", provider = "OpenIdConnect" });

// Default Route
app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();

// Seperate Database Initialisation Method
static async Task InitializeDatabaseAsync(IServiceProvider services)
{
    using var scope = services.CreateScope();
    var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
    var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
    var userManager = scope.ServiceProvider.GetRequiredService<UserManager<IdentityUser>>();
    var userActivityService = scope.ServiceProvider.GetRequiredService<IUserActivityService>();
    var logger = scope.ServiceProvider.GetRequiredService<ILogger<Program>>();

    try
    {
        await context.Database.EnsureCreatedAsync();
        logger.LogInformation("Database created/verified successfully.");

        string[] roles = { "Admin", "User", "Manager", "HR", "HR Manager" };
        foreach (var role in roles)
        {
            if (!await roleManager.RoleExistsAsync(role))
            {
                await roleManager.CreateAsync(new IdentityRole(role));
                logger.LogInformation("Role '{Role}' created.", role);
            }
        }

        // Seeded Admin User
        string adminEmail = "stevenbyrne243@gmail.com";
        string adminPassword = "ComplexP@ssw0rd123!";

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
                logger.LogInformation("Admin user created and assigned Admin role.");

                userActivityService.TrackUserAction(adminUser.Id, "AdminUserCreated", new Dictionary<string, string>
                {
                    ["Email"] = adminEmail,
                    ["CreatedBy"] = "System",
                    ["Timestamp"] = DateTime.UtcNow.ToString("O")
                });
            }
            else
            {
                logger.LogError("Error creating admin user: {Errors}",
                    string.Join(", ", result.Errors.Select(e => e.Description)));
            }
        }
    }
    catch (Exception ex)
    {
        logger.LogError(ex, "Database initialization failed: {Error}", ex.Message);
        throw;
    }
}
    public partial class Program { }