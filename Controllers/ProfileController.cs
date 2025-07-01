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
                // Get the current user from Identity database
                var currentUser = await _userManager.GetUserAsync(User);
                if (currentUser == null)
                {
                    ViewBag.Error = "Unable to load user profile.";
                    return View(new UserProfileViewModel());
                }

                // Get user roles from Identity database
                var userRoles = await _userManager.GetRolesAsync(currentUser);

                // Create the view model with Identity database values
                var model = new UserProfileViewModel
                {
                    DisplayName = currentUser.UserName ?? "No display name found",
                    Email = currentUser.Email ?? "No email found", 
                    PhoneNumber = currentUser.PhoneNumber, 
                    
                    // Authentication and security status
                    IsAuthenticated = User.Identity?.IsAuthenticated ?? false,
                    AuthenticationStatusDisplay = User.Identity?.IsAuthenticated == true ? "Authenticated" : "Not Authenticated",
                    
                    // Roles from Identity database
                    Roles = userRoles.ToList(),
                    HasAdminRole = userRoles.Contains("Admin"),
                    
                    // Identity fields
                    ObjectId = currentUser.Id,
                    EmailConfirmed = currentUser.EmailConfirmed,
                    IsLockedOut = currentUser.LockoutEnd.HasValue && currentUser.LockoutEnd > DateTimeOffset.Now,
                    LockoutEnd = currentUser.LockoutEnd,
                    
                    // Try to get additional info from claims           
                    TenantId = User.FindFirst("tid")?.Value ?? 
                              User.FindFirst("http://schemas.microsoft.com/identity/claims/tenantid")?.Value ?? 
                              "Not available"
                };
                                return View(model);
            }
            catch (Exception ex)
            {
                ViewBag.Error = $"Error loading profile: {ex.Message}";
                return View(new UserProfileViewModel());
            }
        }

    }
}