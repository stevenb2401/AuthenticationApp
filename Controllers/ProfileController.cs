using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using AuthenticationApp.Models; // or Authentication_App.Models

namespace AuthenticationApp.Controllers // or Authentication_App.Controllers
{
    [Authorize]
    public class ProfileController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;

        public ProfileController(UserManager<IdentityUser> userManager)
        {
            _userManager = userManager;
        }

        public async Task<IActionResult> Index()
        {
            return await Details();
        }

        public async Task<IActionResult> Details()
        {
            try
            {
                // Get the current user from Identity database (same source as EditUser)
                var currentUser = await _userManager.GetUserAsync(User);
                if (currentUser == null)
                {
                    ViewBag.Error = "Unable to load user profile.";
                    return View(new UserProfileViewModel());
                }

                // Get user roles from Identity database
                var userRoles = await _userManager.GetRolesAsync(currentUser);

                // Create the view model with Identity database values (SAME AS EDITUSER)
                var model = new UserProfileViewModel
                {
                    // IMPORTANT: These come from the Identity database (same as EditUser)
                    DisplayName = currentUser.UserName ?? "No display name found",
                    Email = currentUser.Email ?? "No email found", 
                    PhoneNumber = currentUser.PhoneNumber, // This will now show the edited phone number
                    
                    // Authentication and security status (from Identity database)
                    IsAuthenticated = User.Identity?.IsAuthenticated ?? false,
                    AuthenticationStatusDisplay = User.Identity?.IsAuthenticated == true ? "Authenticated" : "Not Authenticated",
                    
                    // Roles from Identity database (same as EditUser)
                    Roles = userRoles.ToList(),
                    HasAdminRole = userRoles.Contains("Admin"),
                    
                    // Identity fields (these reflect EditUser changes)
                    ObjectId = currentUser.Id,
                    EmailConfirmed = currentUser.EmailConfirmed,
                    IsLockedOut = currentUser.LockoutEnd.HasValue && currentUser.LockoutEnd > DateTimeOffset.Now,
                    LockoutEnd = currentUser.LockoutEnd,
                    
                    // Try to get additional info from claims (fallback)            
                    TenantId = User.FindFirst("tid")?.Value ?? 
                              User.FindFirst("http://schemas.microsoft.com/identity/claims/tenantid")?.Value ?? 
                              "Not available"
                };

                // Debug output to verify data is being loaded correctly
                Console.WriteLine($"Profile Debug - DisplayName: {model.DisplayName}");
                Console.WriteLine($"Profile Debug - Email: {model.Email}");
                Console.WriteLine($"Profile Debug - PhoneNumber: {model.PhoneNumber ?? "NULL"}");
                Console.WriteLine($"Profile Debug - User ID: {model.ObjectId}");
                Console.WriteLine($"Profile Debug - Roles: {string.Join(", ", model.Roles)}");

                return View(model);
            }
            catch (Exception ex)
            {
                ViewBag.Error = $"Error loading profile: {ex.Message}";
                return View(new UserProfileViewModel());
            }
        }

        [HttpGet]
        public IActionResult Claims()
        {
            var claims = User.Claims.Select(c => new { c.Type, c.Value }).ToList();
            return View(claims);
        }

        [HttpGet]
        public IActionResult DebugClaims()
        {
            var claims = User.Claims.Select(c => new { c.Type, c.Value }).ToList();
            return View(claims);
        }
    }
}