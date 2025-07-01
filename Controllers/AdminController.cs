using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using AuthenticationApp.Models;

namespace AuthenticationApp.Controllers
{
    [Authorize(Policy = "Admin")]
    public class AdminController : Controller
    {
        private readonly ILogger<AdminController> _logger;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;

        public AdminController(
            ILogger<AdminController> logger,
            UserManager<IdentityUser> userManager,
            RoleManager<IdentityRole> roleManager)
        {
            _logger = logger;
            _userManager = userManager;
            _roleManager = roleManager;
        }

        /// <summary>
        /// Admin dashboard showing system overview and management options
        /// </summary>
        public async Task<IActionResult> Index()
        {
            _logger.LogInformation("Admin dashboard accessed by user: {User}", User.Identity?.Name);

            try
            {
                var model = new AdminDashboardViewModel
                {
                    TotalUsers = await _userManager.Users.CountAsync(),
                    TotalRoles = await _roleManager.Roles.CountAsync(),
                    RecentUsers = await _userManager.Users
                        .OrderByDescending(u => u.Id)
                        .Take(5)
                        .Select(u => new UserSummaryViewModel
                        {
                            Id = u.Id,
                            UserName = u.UserName ?? "Unknown",
                            Email = u.Email ?? "No email",
                            EmailConfirmed = u.EmailConfirmed,
                            LockoutEnabled = u.LockoutEnabled,
                            AccessFailedCount = u.AccessFailedCount
                        })
                        .ToListAsync(),
                    SystemRoles = await _roleManager.Roles
                        .Select(r => new RoleViewModel
                        {
                            Id = r.Id,
                            Name = r.Name ?? "Unknown Role",
                            NormalizedName = r.NormalizedName ?? ""
                        })
                        .ToListAsync()
                };

                // Get current admin's roles for display
                var currentUser = await _userManager.GetUserAsync(User);
                if (currentUser != null)
                {
                    model.CurrentAdminRoles = await _userManager.GetRolesAsync(currentUser);
                }

                return View(model);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error loading admin dashboard");
                ViewBag.Error = "Error loading dashboard: " + ex.Message;
                
                // Return a basic model if there's an error
                var errorModel = new AdminDashboardViewModel
                {
                    TotalUsers = 0,
                    TotalRoles = 0
                };
                return View(errorModel);
            }
        }

        /// <summary>
        /// Simple test action to verify controller is working
        /// </summary>
        public IActionResult Test()
        {
            ViewBag.Message = "Admin controller test successful!";
            ViewBag.User = User.Identity?.Name;
            ViewBag.IsAuthenticated = User.Identity?.IsAuthenticated;
            return View();
        }
    }
}