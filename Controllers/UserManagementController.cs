using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using AuthenticationApp.Models;
using System.Security.Claims;

namespace AuthenticationApp.Controllers
{
    [Authorize(Policy = "Admin")]
    public class UserManagementController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly ILogger<UserManagementController> _logger;

        public UserManagementController(
            UserManager<IdentityUser> userManager,
            RoleManager<IdentityRole> roleManager,
            ILogger<UserManagementController> logger)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _logger = logger;
        }
        
        // User management dashboard with search and filtering
        public async Task<IActionResult> Index(UserSearchViewModel? model)
        {
            try
            {
                // Initialises the search model
                if (model == null) model = new UserSearchViewModel();

                var query = _userManager.Users.AsQueryable();
                
                if (!string.IsNullOrEmpty(model.SearchTerm))
                {
                    query = query.Where(u =>
                         (u.UserName ?? string.Empty).Contains(model.SearchTerm) ||
                         (u.Email ?? string.Empty).Contains(model.SearchTerm) ||
                         (u.PhoneNumber ?? string.Empty).Contains(model.SearchTerm));
                }

                if (model.AccountStatus.HasValue)
                {
                    switch (model.AccountStatus.Value)
                    {
                        case UserAccountStatus.Active:
                            query = query.Where(u => !u.LockoutEnabled && u.EmailConfirmed);
                            break;
                        case UserAccountStatus.Disabled:
                            query = query.Where(u => u.LockoutEnabled);
                            break;
                        case UserAccountStatus.Locked:
                            query = query.Where(u => u.LockoutEnd > DateTimeOffset.UtcNow);
                            break;
                        case UserAccountStatus.Unverified:
                            query = query.Where(u => !u.EmailConfirmed);
                            break;
                    }
                }

                if (model.ShowLockedOnly)
                {
                    query = query.Where(u => u.LockoutEnd > DateTimeOffset.UtcNow);
                }

                if (model.ShowUnverifiedOnly)
                {
                    query = query.Where(u => !u.EmailConfirmed);
                }

                // Get total count for pagination
                model.TotalResults = await query.CountAsync();

                var users = await query
                    .Skip((model.CurrentPage - 1) * model.PageSize)
                    .Take(model.PageSize)
                    .ToListAsync();

                model.Results = new List<UserSearchResultViewModel>();
                foreach (var user in users)
                {
                    var userRoles = await _userManager.GetRolesAsync(user);
                    model.Results.Add(new UserSearchResultViewModel
                    {
                        Id = user.Id,
                        UserName = user.UserName ?? string.Empty,
                        Email = user.Email ?? string.Empty,
                        FullName = $"{user.UserName}",
                        IsEnabled = !user.LockoutEnabled,
                        EmailConfirmed = user.EmailConfirmed,
                        IsLockedOut = user.LockoutEnd > DateTimeOffset.UtcNow,
                        AccessFailedCount = user.AccessFailedCount,
                        CreatedDate = DateTime.Now, 
                        Roles = userRoles.ToList()
                    });
                }

                _logger.LogInformation("User management dashboard accessed. Found {Count} users", model.TotalResults);
                return View(model);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error loading user management dashboard");
                TempData["Error"] = "Error loading users. Please try again.";
                return View(new UserSearchViewModel());
            }
        }

        /// Show create user form
        [HttpGet]
        public async Task<IActionResult> Create()
        {
            await Task.CompletedTask;
            
            var model = new Authentication_App.Models.CreateUserViewModel
            {
                AvailableRoles = new List<string> { "Admin", "User", "Manager", "HR", "HR Manager" }
            };

            return View(model);
        }

        // Create a new user
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create(Authentication_App.Models.CreateUserViewModel? model)
        {
            if (model == null)
            {
                return BadRequest("Invalid model data");
            }

            if (!ModelState.IsValid)
            {
                model.AvailableRoles = new List<string> { "Admin", "User", "Manager", "HR", "HR Manager" };
                return View(model);
            }

            try
            {
                // Check if user already exists
                var existingUser = await _userManager.FindByEmailAsync(model.Email);
                if (existingUser != null)
                {
                    ModelState.AddModelError("Email", "A user with this email already exists.");
                    model.AvailableRoles = new List<string> { "Admin", "User", "Manager", "HR", "HR Manager" };
                    return View(model);
                }

                var user = new IdentityUser
                {
                    UserName = model.DisplayName, 
                    Email = model.Email,
                    EmailConfirmed = true, 
                    PhoneNumber = model.PhoneNumber,
                    LockoutEnabled = false
                };

                var result = await _userManager.CreateAsync(user, model.Password);

                if (result.Succeeded)
                {
                    _logger.LogInformation("New user created: {UserName} by admin: {Admin}", 
                        user.UserName, User.Identity?.Name);

                    if (!string.IsNullOrEmpty(model.Role))
                    {
                        await _userManager.AddToRoleAsync(user, model.Role);
                        _logger.LogInformation("Assigned role {Role} to user {UserName}", 
                            model.Role, user.UserName);
                    }

                    TempData["Success"] = $"User '{user.UserName}' created successfully.";
                    return RedirectToAction(nameof(Details), new { id = user.Id });
                }
                else
                {
                    foreach (var error in result.Errors)
                    {
                        ModelState.AddModelError(string.Empty, error.Description);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error creating user {Email}", model.Email);
                ModelState.AddModelError(string.Empty, "An error occurred while creating the user.");
            }

            model.AvailableRoles = new List<string> { "Admin", "User", "Manager", "HR", "HR Manager" };
            return View(model);
        }

        // Show user details
        [HttpGet]
        public async Task<IActionResult> Details(string? id)
        {
            if (string.IsNullOrEmpty(id))
            {
                return NotFound();
            }

            try
            {
                var user = await _userManager.FindByIdAsync(id);
                if (user == null)
                {
                    return NotFound();
                }

                var userRoles = await _userManager.GetRolesAsync(user);
                var userClaims = await _userManager.GetClaimsAsync(user);

                var model = new Authentication_App.Models.EditUserViewModel
                {
                    Id = user.Id,
                    UserName = user.UserName ?? string.Empty,
                    Email = user.Email ?? string.Empty,
                    PhoneNumber = user.PhoneNumber,
                    EmailConfirmed = user.EmailConfirmed,
                    IsLockedOut = user.LockoutEnd.HasValue && user.LockoutEnd > DateTimeOffset.Now,
                    LockoutEnd = user.LockoutEnd,
                    CurrentRoles = userRoles.ToList(),
                    AvailableRoles = new List<string> { "Admin", "User", "Manager", "HR", "HR Manager" }
                };

                return View(model);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error loading user details for {UserId}", id);
                TempData["Error"] = "Error loading user details.";
                return RedirectToAction(nameof(Index));
            }
        }

        // Show edit user form
        [HttpGet]
        public async Task<IActionResult> Edit(string? id)
        {
            if (string.IsNullOrEmpty(id))
            {
                return NotFound();
            }

            try
            {
                var user = await _userManager.FindByIdAsync(id);
                if (user == null)
                {
                    return NotFound();
                }

                var userRoles = await _userManager.GetRolesAsync(user);

                var model = new Authentication_App.Models.EditUserViewModel
                {
                    Id = user.Id,
                    UserName = user.UserName ?? string.Empty,
                    Email = user.Email ?? string.Empty,
                    PhoneNumber = user.PhoneNumber,
                    EmailConfirmed = user.EmailConfirmed,
                    IsLockedOut = user.LockoutEnd.HasValue && user.LockoutEnd > DateTimeOffset.Now,
                    LockoutEnd = user.LockoutEnd,
                    CurrentRoles = userRoles.ToList(),
                    AvailableRoles = new List<string> { "Admin", "User", "Manager", "HR", "HR Manager" },
                    Role = userRoles.FirstOrDefault() ?? string.Empty
                };

                return View(model);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error loading edit form for user {UserId}", id);
                TempData["Error"] = "Error loading user for editing.";
                return RedirectToAction(nameof(Index));
            }
        }

        // Update user information
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Edit(Authentication_App.Models.EditUserViewModel? model)
        {
            if (model == null)
            {
                return BadRequest("Invalid model data");
            }

            if (!ModelState.IsValid)
            {
                model.AvailableRoles = new List<string> { "Admin", "User", "Manager", "HR", "HR Manager" };
                return View(model);
            }

            try
            {
                var user = await _userManager.FindByIdAsync(model.Id);
                if (user == null)
                {
                    return NotFound();
                }

                user.UserName = model.UserName;
                user.Email = model.Email;
                user.PhoneNumber = model.PhoneNumber;
                user.EmailConfirmed = model.EmailConfirmed;

                var result = await _userManager.UpdateAsync(user);

                if (result.Succeeded)
                {
                    _logger.LogInformation("User {UserName} updated by admin {Admin}", 
                        user.UserName, User.Identity?.Name);

                    var currentRoles = await _userManager.GetRolesAsync(user);
                    
                    if (!string.IsNullOrEmpty(model.Role) && !currentRoles.Contains(model.Role))
                    {
                        if (currentRoles.Any())
                        {
                            await _userManager.RemoveFromRolesAsync(user, currentRoles);
                        }
                        
                        await _userManager.AddToRoleAsync(user, model.Role);
                        _logger.LogInformation("Updated role to {Role} for user {UserName}", 
                            model.Role, user.UserName);
                    }

                    TempData["Success"] = $"User '{user.UserName}' updated successfully.";
                    return RedirectToAction(nameof(Details), new { id = model.Id });
                }
                else
                {
                    foreach (var error in result.Errors)
                    {
                        ModelState.AddModelError(string.Empty, error.Description);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error updating user {UserId}", model.Id);
                ModelState.AddModelError(string.Empty, "An error occurred while updating the user.");
            }

            model.AvailableRoles = new List<string> { "Admin", "User", "Manager", "HR", "HR Manager" };
            return View(model);
        }

        // Show password reset form
        [HttpGet]
        public async Task<IActionResult> ResetPassword(string? id)
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

            var model = new ResetPasswordViewModel
            {
                UserId = user.Id,
                UserName = user.UserName ?? string.Empty,
                Email = user.Email ?? string.Empty
            };

            return View(model);
        }

        // Reset user password
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ResetPassword(ResetPasswordViewModel? model)
        {
            if (model == null)
            {
                return BadRequest("Invalid model data");
            }

            if (!ModelState.IsValid)
            {
                return View(model);
            }

            try
            {
                var user = await _userManager.FindByIdAsync(model.UserId);
                if (user == null)
                {
                    return NotFound();
                }

                // Generate password reset token and reset password
                var token = await _userManager.GeneratePasswordResetTokenAsync(user);
                var result = await _userManager.ResetPasswordAsync(user, token, model.NewPassword);

                if (result.Succeeded)
                {
                    _logger.LogInformation("Password reset for user {UserName} by admin {Admin}", 
                        user.UserName, User.Identity?.Name);

                    TempData["Success"] = $"Password reset successfully for user '{user.UserName}'.";
                    return RedirectToAction(nameof(Details), new { id = model.UserId });
                }
                else
                {
                    foreach (var error in result.Errors)
                    {
                        ModelState.AddModelError(string.Empty, error.Description);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error resetting password for user {UserId}", model.UserId);
                ModelState.AddModelError(string.Empty, "An error occurred while resetting the password.");
            }

            return View(model);
        }

        // Toggle user lock status
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ToggleLock(string? id)
        {
            if (string.IsNullOrEmpty(id))
            {
                return NotFound();
            }

            try
            {
                var user = await _userManager.FindByIdAsync(id);
                if (user == null)
                {
                    return NotFound();
                }

                var isLockedOut = await _userManager.IsLockedOutAsync(user);

                if (isLockedOut)
                {
                    await _userManager.SetLockoutEndDateAsync(user, null);
                    _logger.LogInformation("User {UserName} unlocked by admin {Admin}", 
                        user.UserName, User.Identity?.Name);
                    TempData["Success"] = $"User '{user.UserName}' has been unlocked.";
                }
                else
                {
                    await _userManager.SetLockoutEndDateAsync(user, DateTimeOffset.UtcNow.AddYears(100));
                    _logger.LogInformation("User {UserName} locked by admin {Admin}", 
                        user.UserName, User.Identity?.Name);
                    TempData["Success"] = $"User '{user.UserName}' has been locked.";
                }

                return RedirectToAction(nameof(Details), new { id });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error toggling lock status for user {UserId}", id);
                TempData["Error"] = "Error updating user lock status.";
                return RedirectToAction(nameof(Details), new { id });
            }
        }

        /// Deletes user and confirms the process
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Delete(string? id)
        {
            if (string.IsNullOrEmpty(id))
            {
                return NotFound();
            }

            try
            {
                var user = await _userManager.FindByIdAsync(id);
                if (user == null)
                {
                    return NotFound();
                }

                var result = await _userManager.DeleteAsync(user);

                if (result.Succeeded)
                {
                    _logger.LogInformation("User {UserName} deleted by admin {Admin}", 
                        user.UserName, User.Identity?.Name);
                    TempData["Success"] = $"User '{user.UserName}' has been deleted.";
                }
                else
                {
                    TempData["Error"] = "Error deleting user.";
                }

                return RedirectToAction(nameof(Index));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error deleting user {UserId}", id);
                TempData["Error"] = "Error deleting user.";
                return RedirectToAction(nameof(Index));
            }
        }

        #region Helper Methods

        /// Get available roles for selection 
        private async Task<List<RoleSelectionViewModel>> GetAvailableRolesAsync()
        {
            var roles = await _roleManager.Roles.ToListAsync();
            var roleViewModels = new List<RoleSelectionViewModel>();

            foreach (var role in roles)
            {
                var usersInRole = await _userManager.GetUsersInRoleAsync(role.Name ?? string.Empty);
                roleViewModels.Add(new RoleSelectionViewModel
                {
                    RoleId = role.Id,
                    RoleName = role.Name ?? string.Empty,
                    Description = $"Users with {role.Name} privileges",
                    IsSystemRole = role.Name == "Admin" || role.Name == "USER",
                    UserCount = usersInRole.Count
                });
            }

            return roleViewModels.OrderBy(r => r.RoleName).ToList();
        }

        #endregion
    }
}