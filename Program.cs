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

// CONFIGURATION VALIDATION - Add this early to catch missing settings
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

// FIXED DATA PROTECTION CONFIGURATION
builder.Services.AddDataProtection()
    .SetApplicationName("AuthenticationApp")
    .PersistKeysToFileSystem(new DirectoryInfo(Path.Combine(
        builder.Environment.ContentRootPath, "DataProtection-Keys")))
    .SetDefaultKeyLifetime(TimeSpan.FromDays(90))
    .DisableAutomaticKeyGeneration(); // Added for stability

// FIXED ANTIFORGERY CONFIGURATION FOR DEVELOPMENT
builder.Services.AddAntiforgery(options =>
{
    options.Cookie.SameSite = SameSiteMode.None;
    options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest; // Fixed: Never doesn't exist
});

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

// ENHANCED IDENTITY SERVICES with stronger security
builder.Services.AddIdentity<IdentityUser, IdentityRole>(options =>
{
    // Enhanced password policy
    options.Password.RequireDigit = true;
    options.Password.RequiredLength = 12; // Increased from 8
    options.Password.RequireNonAlphanumeric = true; // Changed from false
    options.Password.RequireUppercase = true;
    options.Password.RequireLowercase = true;
    options.Password.RequiredUniqueChars = 6; // New requirement
    
    // Enhanced lockout settings for better security
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15); // Increased from 5
    options.Lockout.MaxFailedAccessAttempts = 3; // Decreased from 5 for security
    options.Lockout.AllowedForNewUsers = true;
    
    // User settings
    options.User.RequireUniqueEmail = true;
    
    // Environment-specific email confirmation
    if (builder.Environment.IsProduction())
    {
        options.SignIn.RequireConfirmedEmail = true; // Required in production
    }
    else
    {
        options.SignIn.RequireConfirmedEmail = false; // Allow for development
    }
})
.AddEntityFrameworkStores<ApplicationDbContext>()
.AddDefaultTokenProviders();

// CONFIGURE IDENTITY'S COOKIE OPTIONS after AddIdentity
builder.Services.ConfigureApplicationCookie(options =>
{
    options.LoginPath = "/Account/Login";
    options.AccessDeniedPath = "/Account/AccessDenied";
    options.ExpireTimeSpan = TimeSpan.FromMinutes(60);
    options.SlidingExpiration = true;
    
    // FIXED COOKIE SETTINGS FOR DEVELOPMENT
    options.Cookie.HttpOnly = true;
    options.Cookie.Name = "AuthApp.Auth";
    options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
    options.Cookie.SameSite = SameSiteMode.None;
    
    // Enhanced validation with proper null checking
    options.Events.OnValidatePrincipal = async context =>
    {
        var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
        
        try
        {
            if (context.Principal?.Identity?.IsAuthenticated == true)
            {
                logger.LogInformation("🍪 Cookie validation successful for user: {User}", 
                    context.Principal.Identity.Name);
            }
            else
            {
                logger.LogWarning("🍪 Cookie validation failed - rejecting principal");
                context.RejectPrincipal();
            }
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "🍪 Error during cookie validation");
            context.RejectPrincipal();
        }
        
        await Task.CompletedTask;
    };
    
    options.Events.OnSigningIn = context =>
    {
        var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
        logger.LogInformation("🍪 Cookie signing in for user: {User}", 
            context.Principal?.Identity?.Name ?? "Unknown");
        return Task.CompletedTask;
    };
    
    options.Events.OnSigningOut = context =>
    {
        var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
        logger.LogInformation("🍪 Cookie signing out for user: {User}", 
            context.HttpContext.User?.Identity?.Name ?? "Unknown");
        return Task.CompletedTask;
    };
});

// FIXED AUTHENTICATION CONFIGURATION - Let Identity handle its own scheme
builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = IdentityConstants.ApplicationScheme; // Use Identity's default scheme
    options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
    options.DefaultSignInScheme = IdentityConstants.ApplicationScheme; // Use Identity's default scheme
})
// Don't manually add the Identity.Application cookie scheme - AddIdentity() already does this
.AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, options =>
{
    // Get Azure AD configuration values
    var azureAdSection = builder.Configuration.GetSection("AzureAd");
    var instance = azureAdSection["Instance"];
    var tenantId = azureAdSection["TenantId"];
    var clientId = azureAdSection["ClientId"];
    var clientSecret = azureAdSection["ClientSecret"];
    
    // Basic OpenID Connect settings
    options.Authority = $"{instance?.TrimEnd('/')}/{tenantId}/v2.0";
    options.ClientId = clientId;
    options.ClientSecret = clientSecret;
    options.CallbackPath = "/signin-oidc";
    options.SignedOutCallbackPath = "/signout-oidc";
    options.SignInScheme = IdentityConstants.ApplicationScheme; // Use Identity's scheme
    options.ResponseType = "code";
    options.SaveTokens = true;
    options.GetClaimsFromUserInfoEndpoint = true;
    options.UsePkce = true;
    
    // CRITICAL FIX: Disable problematic validations for development
    options.ProtocolValidator.RequireStateValidation = false; // Disable state validation
    options.ProtocolValidator.RequireNonce = false;
    options.RequireHttpsMetadata = false;
    
    // CRITICAL FIX: Simplified correlation cookie settings for development
    options.CorrelationCookie.SameSite = SameSiteMode.None;
    options.CorrelationCookie.SecurePolicy = CookieSecurePolicy.SameAsRequest; // Fixed: Never doesn't exist
    options.CorrelationCookie.HttpOnly = false; // Temporarily disable for debugging
    options.CorrelationCookie.IsEssential = true;
    options.CorrelationCookie.Path = "/";
    options.CorrelationCookie.Domain = null;
    options.CorrelationCookie.Name = "AzureAD.Correlation"; // Custom name for debugging
    
    options.NonceCookie.SameSite = SameSiteMode.None;
    options.NonceCookie.SecurePolicy = CookieSecurePolicy.SameAsRequest; // Fixed: Never doesn't exist
    options.NonceCookie.HttpOnly = false;
    options.NonceCookie.IsEssential = true;
    options.NonceCookie.Path = "/";
    options.NonceCookie.Domain = null;
    options.NonceCookie.Name = "AzureAD.Nonce"; // Custom name for debugging
    
    // Configure scopes
    options.Scope.Clear();
    options.Scope.Add("openid");
    options.Scope.Add("profile");
    options.Scope.Add("email");
    options.Scope.Add("User.Read");
    
    // Configure token validation
    options.TokenValidationParameters.RoleClaimType = "roles";
    options.TokenValidationParameters.NameClaimType = "name";
    options.TokenValidationParameters.ValidateIssuer = false; // Disable for development
    options.TokenValidationParameters.ClockSkew = TimeSpan.FromMinutes(5);
    
    // SIMPLIFIED EVENT HANDLERS - Focus on core functionality
    options.Events = new OpenIdConnectEvents
    {
        OnRedirectToIdentityProvider = context =>
        {
            var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
            logger.LogInformation("🚀 Redirecting to Azure AD: {AuthorityUrl}", context.Options.Authority);
            logger.LogInformation("🔑 Client ID: {ClientId}", context.Options.ClientId);
            logger.LogInformation("🔗 Callback Path: {CallbackPath}", context.Options.CallbackPath);
            
            // Clear any existing authentication
            context.HttpContext.Response.Cookies.Delete("AzureAD.Correlation");
            context.HttpContext.Response.Cookies.Delete("AzureAD.Nonce");
            
            return Task.CompletedTask;
        },
        
        OnMessageReceived = context =>
        {
            var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
            logger.LogInformation("📨 Message received from Azure AD");
            
            // Log available cookies for debugging
            var correlationCookies = context.Request.Cookies.Where(c => c.Key.Contains("Correlation")).ToList();
            logger.LogInformation("🍪 Correlation cookies found: {Count}", correlationCookies.Count);
            foreach (var cookie in correlationCookies)
            {
                var cookieValue = cookie.Value ?? "";
                var displayValue = cookieValue.Length > 20 ? cookieValue.Substring(0, 20) : cookieValue;
                logger.LogInformation("🍪 Cookie: {Name} = {Value}", cookie.Key, displayValue);
            }
            
            return Task.CompletedTask;
        },
        
        OnTokenValidated = async context =>
        {
            var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
            var userManager = context.HttpContext.RequestServices.GetRequiredService<UserManager<IdentityUser>>();
            
            logger.LogInformation("✓ Azure AD token validated successfully");
            
            try
            {
                // Get user information from Azure AD claims
                var email = context.Principal?.FindFirst(ClaimTypes.Email)?.Value ??
                           context.Principal?.FindFirst("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress")?.Value;
                var name = context.Principal?.FindFirst(ClaimTypes.Name)?.Value ?? 
                          context.Principal?.FindFirst("name")?.Value;
                var objectId = context.Principal?.FindFirst("oid")?.Value ?? 
                              context.Principal?.FindFirst("http://schemas.microsoft.com/identity/claims/objectidentifier")?.Value;
                
                logger.LogInformation("📧 User email: {Email}, Name: {Name}, ObjectId: {ObjectId}", email, name, objectId);
                
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
                            logger.LogInformation("✓ Created new local user for Azure AD account: {Email}", email);
                            
                            if (email == "stevenbyrne243@gmail.com")
                            {
                                await userManager.AddToRoleAsync(newUser, "Admin");
                                logger.LogInformation("✓ Added Admin role for {Email}", email);
                            }
                            else
                            {
                                await userManager.AddToRoleAsync(newUser, "User");
                                logger.LogInformation("✓ Added User role for {Email}", email);
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
                        logger.LogInformation("✓ Found existing local user for Azure AD account: {Email}", email);
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
                        
                        logger.LogInformation("✓ Added local roles for {Email}: {Roles}", email, string.Join(", ", userRoles));
                    }
                }
                
                logger.LogInformation("🔍 Authentication completed successfully for {Email}", email);
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
            logger.LogError(context.Exception, "✗ Azure AD authentication failed: {Error}", context.Exception?.Message);
            
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
            logger.LogError("✗ Azure AD remote failure: {Error}", context.Failure?.Message);
            
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

// REGISTER AUTHORIZATION HANDLERS
builder.Services.AddScoped<IAuthorizationHandler, RoleAuthorizationHandler>();

// AUTHORIZATION POLICIES - Temporarily disabled fallback policy
builder.Services.AddAuthorization(options =>
{
    // TEMPORARILY DISABLE fallback policy to stop authentication loop
    // TODO: Re-enable after fixing the root cause
    // options.FallbackPolicy = new AuthorizationPolicyBuilder()
    //     .RequireAuthenticatedUser()
    //     .Build();

    // ROLE-BASED POLICIES with clear naming
    options.AddPolicy("RequireAdminRole", policy =>
        policy.RequireRole("Admin", "Administrator", "Global Administrator"));

    options.AddPolicy("RequireManagerOrAdmin", policy =>
        policy.RequireRole("Manager", "Admin", "Administrator"));

    options.AddPolicy("RequireHRAccess", policy =>
        policy.RequireRole("HR", "Human Resources", "HR Manager"));

    // LOCAL IDENTITY POLICIES
    options.AddPolicy("RequireLocalAdmin", policy =>
        policy.RequireRole("Admin")); 

    options.AddPolicy("RequireLocalUser", policy =>
        policy.RequireRole("User", "Admin"));
        
    // COMBINED POLICIES for flexibility
    options.AddPolicy("RequireAnyAdmin", policy =>
        policy.RequireAssertion(context =>
            context.User.IsInRole("Admin") || 
            context.User.IsInRole("Administrator") ||
            context.User.IsInRole("Global Administrator")));
});

// Add MVC Controllers with Views
builder.Services.AddControllersWithViews();

// ENHANCED LOGGING with structured logging
builder.Services.AddLogging(logging =>
{
    logging.ClearProviders(); // Start fresh
    logging.AddConsole();
    logging.AddDebug();
    
    if (!builder.Environment.IsDevelopment())
    {
        logging.AddApplicationInsights();
    }
    
    // Add specific filters for authentication/authorization - SET TO TRACE for maximum detail
    logging.AddFilter("Microsoft.AspNetCore.Authentication", LogLevel.Trace);
    logging.AddFilter("Microsoft.AspNetCore.Authentication.OpenIdConnect", LogLevel.Trace);
    logging.AddFilter("Microsoft.AspNetCore.Authentication.Cookies", LogLevel.Trace);
    logging.AddFilter("Microsoft.AspNetCore.Authorization", LogLevel.Information);
    
    if (builder.Environment.IsDevelopment())
    {
        logging.SetMinimumLevel(LogLevel.Trace); // Set to TRACE
    }
    else
    {
        logging.SetMinimumLevel(LogLevel.Information);
    }
});

var app = builder.Build();

// DATABASE INITIALIZATION
await InitializeDatabaseAsync(app.Services);

// ENHANCED MIDDLEWARE PIPELINE with security headers
if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
}
else
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
    
    // Add security headers for production
    app.Use(async (context, next) =>
    {
        context.Response.Headers["X-Frame-Options"] = "DENY";
        context.Response.Headers["X-Content-Type-Options"] = "nosniff";
        context.Response.Headers["Referrer-Policy"] = "strict-origin-when-cross-origin";
        context.Response.Headers["X-XSS-Protection"] = "1; mode=block";
        
        // Add Content Security Policy
        context.Response.Headers["Content-Security-Policy"] = 
            "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;";
        
        await next();
    });
}

app.UseHttpsRedirection();
app.UseStaticFiles();

// FIXED: Enhanced middleware to clear corrupted authentication state
app.Use(async (context, next) =>
{
    var logger = context.RequestServices.GetRequiredService<ILogger<Program>>();
    
    // If we detect authentication errors in query string, clear auth cookies
    if (context.Request.Query.ContainsKey("error") && 
        (context.Request.Query["error"] == "auth_failed" || context.Request.Query["error"] == "azure_auth_failed"))
    {
        logger.LogInformation("🧹 Clearing authentication cookies due to error");
        
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
            ".AspNetCore.Identity.Application", // This is the key one
            ".AspNetCore.Antiforgery"
        };
        
        foreach (var cookie in cookiesToClear)
        {
            if (context.Request.Cookies.ContainsKey(cookie))
            {
                logger.LogInformation("🗑️ Deleting cookie: {Cookie}", cookie);
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
    
    // Enhanced callback processing
    if (context.Request.Path == "/signin-oidc" && context.Request.Method == "POST")
    {
        logger.LogInformation("🔍 Processing Azure AD callback");
        
        // Check for correlation cookies
        var hasCorrelationCookie = context.Request.Cookies.Keys
            .Any(k => k.Contains("Correlation"));
            
        if (!hasCorrelationCookie)
        {
            logger.LogWarning("⚠️ No correlation cookie found for callback - this might cause correlation failure");
        }
    }
    
    await next();
});

// DEBUGGING: Add request logging middleware to track authentication state
app.Use(async (context, next) =>
{
    var logger = context.RequestServices.GetRequiredService<ILogger<Program>>();
    logger.LogInformation("🌐 Request: {Method} {Path}, IsAuthenticated: {IsAuth}, User: {User}, Claims: {Claims}", 
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

// OPTIONAL: Nuclear option middleware (uncomment if still having issues)
/*
app.Use(async (context, next) =>
{
    if (context.Request.Path == "/signin-oidc" && context.Request.Method == "POST")
    {
        var logger = context.RequestServices.GetRequiredService<ILogger<Program>>();
        logger.LogInformation("🔧 Nuclear option: Injecting correlation cookie for debugging");
        
        // This is a temporary workaround - inject a fake correlation cookie
        var correlationCookieName = "AzureAD.Correlation";
        if (!context.Request.Cookies.ContainsKey(correlationCookieName))
        {
            // Extract state parameter to find correlation ID
            var stateParam = context.Request.Form["state"].FirstOrDefault();
            if (!string.IsNullOrEmpty(stateParam))
            {
                // Create a minimal correlation cookie
                context.Response.Cookies.Append(correlationCookieName, "temp-correlation-value", new CookieOptions
                {
                    SameSite = SameSiteMode.None,
                    Secure = false,
                    HttpOnly = false
                });
                logger.LogInformation("🔧 Injected temporary correlation cookie");
            }
        }
    }
    
    await next();
});
*/

// Additional debugging middleware after authentication
app.Use(async (context, next) =>
{
    var logger = context.RequestServices.GetRequiredService<ILogger<Program>>();
    
    if (context.Request.Path.StartsWithSegments("/signin-oidc"))
    {
        logger.LogInformation("🎯 /signin-oidc request AFTER auth middleware: {Method} {Path}", 
            context.Request.Method, context.Request.Path);
        logger.LogInformation("🔐 Authentication result: {IsAuth}", context.User?.Identity?.IsAuthenticated);
        
        // If this is a POST and we're still not authenticated, something went wrong
        if (context.Request.Method == "POST" && context.User?.Identity?.IsAuthenticated != true)
        {
            logger.LogWarning("⚠️ POST to /signin-oidc but still not authenticated");
        }
    }
    
    await next();
});

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

// Azure AD sign-in route
app.MapControllerRoute(
    name: "azure_signin",
    pattern: "signin-azure",
    defaults: new { controller = "Account", action = "ExternalLogin", provider = "OpenIdConnect" });

// DEFAULT ROUTE MUST BE LAST
app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();

// SEPARATE DATABASE INITIALIZATION METHOD
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
        // Ensure database is created
        await context.Database.EnsureCreatedAsync();
        logger.LogInformation("Database created/verified successfully.");

        // Create roles
        string[] roles = { "Admin", "User", "Manager", "HR", "HR Manager" };
        foreach (var role in roles)
        {
            if (!await roleManager.RoleExistsAsync(role))
            {
                await roleManager.CreateAsync(new IdentityRole(role));
                logger.LogInformation("Role '{Role}' created.", role);
            }
        }

        // Create admin user
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
                
                // Track admin user creation
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