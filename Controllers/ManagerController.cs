using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using AuthenticationApp.Models;

namespace AuthenticationApp.Controllers
{
    [Authorize(Policy = "Manager_or_Admin")]
    public class ManagerController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IAuthorizationService _authorizationService;

        public ManagerController(
            UserManager<IdentityUser> userManager, 
            RoleManager<IdentityRole> roleManager,
            IAuthorizationService authorizationService)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _authorizationService = authorizationService;
        }

        public async Task<IActionResult> Index()
        {
            var model = new ManagerDashboardViewModel
            {
                CurrentUser = User.Identity?.Name ?? "Unknown",
                TotalUsers = await _userManager.Users.CountAsync(),
                ActiveUsers = await _userManager.Users.Where(u => u.EmailConfirmed).CountAsync(),
                TotalRoles = await _roleManager.Roles.CountAsync(),
                RecentUsers = await _userManager.Users
                    .OrderByDescending(u => u.Id)
                    .Take(5)
                    .Select(u => new UserSummaryViewModel
                    {
                        Id = u.Id,
                        UserName = u.UserName,
                        Email = u.Email,
                        EmailConfirmed = u.EmailConfirmed,
                        LockoutEnabled = u.LockoutEnabled
                    })
                    .ToListAsync()
            };

            // Get role distribution
            var roles = await _roleManager.Roles.ToListAsync();
            foreach (var role in roles)
            {
                var usersInRole = await _userManager.GetUsersInRoleAsync(role.Name!);
                model.RoleDistribution.Add(role.Name!, usersInRole.Count);
            }

            return View(model);
        }

        [HttpGet]
        public async Task<IActionResult> TeamOverview()
        {
            var users = await _userManager.Users.ToListAsync();
            var userViewModels = new List<TeamMemberViewModel>();

            foreach (var user in users)
            {
                var roles = await _userManager.GetRolesAsync(user);
                userViewModels.Add(new TeamMemberViewModel
                {
                    Id = user.Id,
                    UserName = user.UserName,
                    Email = user.Email,
                    EmailConfirmed = user.EmailConfirmed,
                    IsLockedOut = user.LockoutEnd.HasValue && user.LockoutEnd > DateTimeOffset.Now,
                    Roles = roles.ToList()
                });
            }

            return View(userViewModels);
        }

        [HttpGet]
        public async Task<IActionResult> UserRoles(string id)
        {
            if (string.IsNullOrEmpty(id))
            {
                return NotFound();
            }

            var user = await _userManager.FindByIdAsync(id);
            if (user == null)
            {
                return NotFound();
            }

            var userRoles = await _userManager.GetRolesAsync(user);
            var allRoles = await _roleManager.Roles.Select(r => r.Name).ToListAsync();

            var model = new UserRoleManagementViewModel
            {
                UserId = user.Id,
                UserName = user.UserName,
                Email = user.Email,
                CurrentRoles = userRoles.ToList(),
                AvailableRoles = allRoles!
            };

            return View(model);
        }

        [HttpPost]
        public async Task<IActionResult> AssignRole(string userId, string roleName)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return Json(new { success = false, message = "User not found" });
            }

            if (!await _roleManager.RoleExistsAsync(roleName))
            {
                return Json(new { success = false, message = "Role does not exist" });
            }

            var result = await _userManager.AddToRoleAsync(user, roleName);
            if (result.Succeeded)
            {
                return Json(new { success = true, message = $"Role '{roleName}' assigned successfully" });
            }

            return Json(new { success = false, message = string.Join(", ", result.Errors.Select(e => e.Description)) });
        }

        [HttpPost]
        public async Task<IActionResult> RemoveRole(string userId, string roleName)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return Json(new { success = false, message = "User not found" });
            }

            var result = await _userManager.RemoveFromRoleAsync(user, roleName);
            if (result.Succeeded)
            {
                return Json(new { success = true, message = $"Role '{roleName}' removed successfully" });
            }

            return Json(new { success = false, message = string.Join(", ", result.Errors.Select(e => e.Description)) });
        }

        [HttpGet]
        public async Task<IActionResult> Reports()
        {
            var model = new ManagerReportsViewModel
            {
                TotalUsers = await _userManager.Users.CountAsync(),
                ActiveUsers = await _userManager.Users.Where(u => u.EmailConfirmed).CountAsync(),
                LockedUsers = await _userManager.Users.Where(u => u.LockoutEnd.HasValue && u.LockoutEnd > DateTimeOffset.Now).CountAsync(),
                UnverifiedUsers = await _userManager.Users.Where(u => !u.EmailConfirmed).CountAsync(),
                RecentRegistrations = await _userManager.Users
                    .OrderByDescending(u => u.Id)
                    .Take(10)
                    .ToListAsync()
            };

            return View(model);
        }
    }
}