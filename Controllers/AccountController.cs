using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Authentication_App.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authentication;
using Microsoft.EntityFrameworkCore; // Add this for ToListAsync

namespace Authentication_App.Controllers
{
    public class AccountController : Controller
    {
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly ILogger<AccountController> _logger;

        public AccountController(SignInManager<IdentityUser> signInManager, UserManager<IdentityUser> userManager, ILogger<AccountController> logger)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _logger = logger;
        }

        // GET login page with authentication options
        [HttpGet]
        [AllowAnonymous]
        [Route("signin")]
        public IActionResult Login(string returnUrl = "/")
        {
            ViewData["ReturnUrl"] = returnUrl;
            ViewData["Title"] = "Login";

            return View(new LoginViewModel());
        }

        // POST local login - FIXED VERSION
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        [Route("signin")]
        public async Task<IActionResult> Login(LoginViewModel model, string returnUrl = "/")
        {
            ViewData["ReturnUrl"] = returnUrl;
            ViewData["Title"] = "Login";

            if (ModelState.IsValid)
            {
                IdentityUser? user = null;
                
                // Try to find user by email first
                if (model.Email.Contains("@"))
                {
                    user = await _userManager.FindByEmailAsync(model.Email);
                    _logger.LogInformation("Searching by email: {Email}", model.Email);
                }
                else
                {
                    // If no @ symbol, treat as username
                    user = await _userManager.FindByNameAsync(model.Email);
                    _logger.LogInformation("Searching by username: {Username}", model.Email);
                }
                
                if (user != null)
                {
                    _logger.LogInformation("Found user {Email} with username {UserName}", user.Email, user.UserName);
                    
                    // Use the actual username for sign in
                    var result = await _signInManager.PasswordSignInAsync(
                        user.UserName!, // Use the username from the found user
                        model.Password,
                        model.RememberMe,
                        lockoutOnFailure: true
                    );

                    if (result.Succeeded)
                    {
                        _logger.LogInformation("User {Email} logged in successfully", user.Email ?? user.UserName);
                        return LocalRedirect(returnUrl);
                    }

                    if (result.IsLockedOut)
                    {
                        _logger.LogWarning("User {Email} account locked out", user.Email ?? user.UserName);
                        ModelState.AddModelError(string.Empty, "Your account is locked.");
                    }
                    else if (result.RequiresTwoFactor)
                    {
                        _logger.LogInformation("User {Email} requires two factor authentication", user.Email ?? user.UserName);
                        ModelState.AddModelError(string.Empty, "Two-factor authentication required.");
                    }
                    else
                    {
                        _logger.LogWarning("Invalid password attempt for user {Email}", user.Email ?? user.UserName);
                        ModelState.AddModelError(string.Empty, "Invalid login attempt.");
                    }
                }
                else
                {
                    _logger.LogWarning("Login attempt with non-existent email/username: {EmailOrUsername}", model.Email);
                    ModelState.AddModelError(string.Empty, "Invalid login attempt.");
                }
            }
            else
            {
                _logger.LogWarning("Login attempt with invalid model state");
            }

            return View(model);
        }

        // Azure AD login
        [HttpGet]
        [AllowAnonymous]
        [Route("signin-azure")]
        public IActionResult LoginAzure(string returnUrl = "/")
        {
            var redirectUrl = Url.Action("AzureCallback", "Account", new { returnUrl });
            var properties = new AuthenticationProperties { RedirectUri = redirectUrl };
            return Challenge(properties, OpenIdConnectDefaults.AuthenticationScheme);
        }

        // Azure AD callback
        [HttpGet]
        [AllowAnonymous]
        public IActionResult AzureCallback(string returnUrl = "/")
        {
            return LocalRedirect(returnUrl);
        }

        // GET access denied page
        [HttpGet]
        public IActionResult AccessDenied()
        {
            ViewData["Title"] = "Access Denied";
            return View();
        }

        // Logout (handles both local and Azure)
        [HttpGet("logout")]
        public async Task<IActionResult> Logout()
        {
            await _signInManager.SignOutAsync();
            return SignOut(
                new AuthenticationProperties { RedirectUri = "/" },
                OpenIdConnectDefaults.AuthenticationScheme
            );
        }

        // Debug method to unlock admin account
        [AllowAnonymous]
        [HttpGet("unlock-admin")]
        public async Task<IActionResult> UnlockAdmin()
        {
            try
            {
                var user = await _userManager.FindByNameAsync("Steven_Byrne");
                if (user == null)
                {
                    return Json(new { success = false, message = "User Steven_Byrne not found" });
                }

                // Unlock the account
                var unlockResult = await _userManager.SetLockoutEndDateAsync(user, null);
                
                // Reset failed access count
                var resetResult = await _userManager.ResetAccessFailedCountAsync(user);

                if (unlockResult.Succeeded && resetResult.Succeeded)
                {
                    _logger.LogInformation("Account unlocked for user {Username}", user.UserName);
                    return Json(new { 
                        success = true, 
                        message = "Account unlocked successfully",
                        username = user.UserName,
                        email = user.Email,
                        lockoutEnd = user.LockoutEnd,
                        accessFailedCount = user.AccessFailedCount
                    });
                }
                else
                {
                    return Json(new { success = false, message = "Failed to unlock account" });
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error unlocking admin account");
                return Json(new { success = false, message = ex.Message });
            }
        }

        // Debug method to reset admin password
        [AllowAnonymous]
        [HttpGet("reset-admin-password")]
        public async Task<IActionResult> ResetAdminPassword()
        {
            try
            {
                var user = await _userManager.FindByNameAsync("Steven_Byrne");
                if (user == null)
                {
                    return Json(new { success = false, message = "User Steven_Byrne not found" });
                }

                // First, completely unlock the account
                await _userManager.SetLockoutEndDateAsync(user, null);
                await _userManager.ResetAccessFailedCountAsync(user);
                
                // Disable lockout for this user
                await _userManager.SetLockoutEnabledAsync(user, false);

                // Reset password to known value
                var token = await _userManager.GeneratePasswordResetTokenAsync(user);
                var result = await _userManager.ResetPasswordAsync(user, token, "P@$$w0rd01");

                if (result.Succeeded)
                {
                    // Ensure user has admin role
                    if (!await _userManager.IsInRoleAsync(user, "Admin"))
                    {
                        await _userManager.AddToRoleAsync(user, "Admin");
                    }

                    // Reload user to get updated values
                    user = await _userManager.FindByNameAsync("Steven_Byrne");

                    _logger.LogInformation("Password reset and account unlocked for user {Username}", user.UserName);
                    return Json(new { 
                        success = true, 
                        message = "Password reset to P@$$w0rd01 and account unlocked",
                        username = user.UserName,
                        email = user.Email,
                        lockoutEnd = user.LockoutEnd,
                        lockoutEnabled = user.LockoutEnabled,
                        accessFailedCount = user.AccessFailedCount
                    });
                }
                else
                {
                    var errors = string.Join(", ", result.Errors.Select(e => e.Description));
                    _logger.LogError("Password reset failed: {Errors}", errors);
                    return Json(new { success = false, message = errors });
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error resetting admin password");
                return Json(new { success = false, message = ex.Message });
            }
        }

        // Nuclear option: Force unlock via direct database update
        [AllowAnonymous]
        [HttpGet("force-unlock-admin")]
        public async Task<IActionResult> ForceUnlockAdmin()
        {
            try
            {
                var user = await _userManager.FindByNameAsync("Steven_Byrne");
                if (user == null)
                {
                    return Json(new { success = false, message = "User Steven_Byrne not found" });
                }

                // Direct property updates
                user.LockoutEnd = null;
                user.LockoutEnabled = false;
                user.AccessFailedCount = 0;

                // Update user directly
                var updateResult = await _userManager.UpdateAsync(user);

                // Reset password
                var token = await _userManager.GeneratePasswordResetTokenAsync(user);
                var passwordResult = await _userManager.ResetPasswordAsync(user, token, "P@$$w0rd01");

                if (updateResult.Succeeded && passwordResult.Succeeded)
                {
                    // Ensure admin role
                    if (!await _userManager.IsInRoleAsync(user, "Admin"))
                    {
                        await _userManager.AddToRoleAsync(user, "Admin");
                    }

                    _logger.LogInformation("Force unlock and password reset successful for user {Username}", user.UserName);
                    return Json(new { 
                        success = true, 
                        message = "Account force unlocked and password reset to P@$$w0rd01",
                        username = user.UserName,
                        email = user.Email,
                        lockoutEnd = user.LockoutEnd,
                        lockoutEnabled = user.LockoutEnabled,
                        accessFailedCount = user.AccessFailedCount
                    });
                }
                else
                {
                    var errors = new List<string>();
                    if (!updateResult.Succeeded)
                        errors.AddRange(updateResult.Errors.Select(e => e.Description));
                    if (!passwordResult.Succeeded)
                        errors.AddRange(passwordResult.Errors.Select(e => e.Description));
                    
                    return Json(new { success = false, message = string.Join(", ", errors) });
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error force unlocking admin account");
                return Json(new { success = false, message = ex.Message });
            }
        }

        // Nuclear fix for Steven_Byrne specifically
        [AllowAnonymous]
        [HttpGet("fix-steven-byrne")]
        public async Task<IActionResult> FixStevenByrne()
        {
            try
            {
                var user = await _userManager.FindByNameAsync("Steven_Byrne");
                if (user == null)
                {
                    return Json(new { success = false, message = "User Steven_Byrne not found" });
                }

                // Force unlock by setting past date
                user.LockoutEnd = DateTimeOffset.UtcNow.AddDays(-1);
                user.LockoutEnabled = false;
                user.AccessFailedCount = 0;

                // Update user
                var updateResult = await _userManager.UpdateAsync(user);

                if (updateResult.Succeeded)
                {
                    // Generate new password reset token
                    var token = await _userManager.GeneratePasswordResetTokenAsync(user);
                    var passwordResult = await _userManager.ResetPasswordAsync(user, token, "P@$$w0rd01");

                    if (passwordResult.Succeeded)
                    {
                        // Final update to ensure changes stick
                        user.LockoutEnd = null;
                        user.LockoutEnabled = false;
                        await _userManager.UpdateAsync(user);

                        return Json(new { 
                            success = true, 
                            message = "Steven_Byrne fixed successfully",
                            username = user.UserName,
                            email = user.Email,
                            lockoutEnd = user.LockoutEnd,
                            lockoutEnabled = user.LockoutEnabled,
                            accessFailedCount = user.AccessFailedCount,
                            password = "P@$$w0rd01"
                        });
                    }
                    else
                    {
                        return Json(new { 
                            success = false, 
                            message = "Password reset failed: " + string.Join(", ", passwordResult.Errors.Select(e => e.Description))
                        });
                    }
                }
                else
                {
                    return Json(new { 
                        success = false, 
                        message = "User update failed: " + string.Join(", ", updateResult.Errors.Select(e => e.Description))
                    });
                }
            }
            catch (Exception ex)
            {
                return Json(new { success = false, message = ex.Message });
            }
        }

        // Create a brand new admin user
        [AllowAnonymous]
        [HttpGet("create-new-admin")]
        public async Task<IActionResult> CreateNewAdmin()
        {
            try
            {
                // Delete existing problematic user
                var existingUser = await _userManager.FindByNameAsync("Steven_Byrne");
                if (existingUser != null)
                {
                    await _userManager.DeleteAsync(existingUser);
                    _logger.LogInformation("Deleted existing user Steven_Byrne");
                }

                // Create fresh admin user
                var newAdmin = new IdentityUser
                {
                    UserName = "admin",
                    Email = "admin@localhost.com",
                    EmailConfirmed = true,
                    LockoutEnabled = false
                };

                var result = await _userManager.CreateAsync(newAdmin, "P@$$w0rd01");

                if (result.Succeeded)
                {
                    await _userManager.AddToRoleAsync(newAdmin, "Admin");
                    
                    _logger.LogInformation("New admin user created successfully");
                    return Json(new { 
                        success = true, 
                        message = "New admin user created successfully",
                        username = newAdmin.UserName,
                        email = newAdmin.Email,
                        password = "P@$$w0rd01"
                    });
                }
                else
                {
                    var errors = string.Join(", ", result.Errors.Select(e => e.Description));
                    return Json(new { success = false, message = errors });
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error creating new admin user");
                return Json(new { success = false, message = ex.Message });
            }
        }

        // Debug method to check users in database
        [AllowAnonymous]
        [HttpGet("debug-users")]
        public async Task<IActionResult> DebugUsers()
        {
            try
            {
                var users = await _userManager.Users.ToListAsync();
                var userInfo = new List<object>();
                
                foreach (var user in users)
                {
                    var roles = await _userManager.GetRolesAsync(user);
                    userInfo.Add(new
                    {
                        Id = user.Id,
                        UserName = user.UserName,
                        Email = user.Email,
                        NormalizedUserName = user.NormalizedUserName,
                        NormalizedEmail = user.NormalizedEmail,
                        EmailConfirmed = user.EmailConfirmed,
                        LockoutEnabled = user.LockoutEnabled,
                        LockoutEnd = user.LockoutEnd,
                        AccessFailedCount = user.AccessFailedCount,
                        Roles = roles
                    });
                }
                
                return Json(userInfo);
            }
            catch (Exception ex)
            {
                return Json(new { error = ex.Message });
            }
        }
    }
}