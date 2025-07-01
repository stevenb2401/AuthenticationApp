using Authentication_App.Models; // Add this to reference your ViewModels
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace Authentication_App.Controllers
{
    [Authorize]
    public class UserController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;

        public UserController(UserManager<IdentityUser> userManager, RoleManager<IdentityRole> roleManager)
        {
            _userManager = userManager;
            _roleManager = roleManager;
        }

        // GET method for rendering the Create User form
        [HttpGet]
        [Authorize(Roles = "Admin")] // Only admins can create users
        public IActionResult CreateUser()
        {
            return View(new CreateUserViewModel());
        }

        // POST method for handling Create User form submission
        [HttpPost]
        [Authorize(Roles = "Admin")] // Only admins can create users
        public async Task<IActionResult> CreateUser(CreateUserViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model); // Returns the form if there are any validation errors
            }

            var user = new IdentityUser
            {
                UserName = model.DisplayName, 
                Email = model.Email,
                EmailConfirmed = true,
                PhoneNumber = model.PhoneNumber 
            };

            var result = await _userManager.CreateAsync(user, model.Password);
            if (result.Succeeded)
            {
                if (!string.IsNullOrEmpty(model.Role))
                {
                    await _userManager.AddToRoleAsync(user, model.Role);
                }

                TempData["SuccessMessage"] = $"User {model.DisplayName} ({model.Email}) created successfully!";
                return RedirectToAction("UserList"); // Redirect to the User List page
            }

            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }

            return View(model);
        }

        // GET method for displaying the User List
        [Authorize(Roles = "Admin")] // Only admins can view user list
        public IActionResult UserList()
        {
            var users = _userManager.Users.ToList();
            return View(users); // Pass the list of users to the UserList view
        }

        // GET method for rendering the Edit User form
        [HttpGet]
        public async Task<IActionResult> EditUser(string id)
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

            var currentUser = await _userManager.GetUserAsync(User);
            
            // Check if user is admin OR editing their own profile
            if (!User.IsInRole("Admin") && currentUser?.Id != id)
            {
                return Forbid(); // Not admin and not own profile
            }

            var userRoles = await _userManager.GetRolesAsync(user);

            // Get the user's primary role
            var primaryRole = userRoles.FirstOrDefault() ?? string.Empty;

            var model = new EditUserViewModel
            {
                Id = user.Id,
                UserName = user.UserName ?? string.Empty,
                Email = user.Email ?? string.Empty,
                PhoneNumber = user.PhoneNumber,
                Role = primaryRole,
                EmailConfirmed = user.EmailConfirmed,
                IsLockedOut = user.LockoutEnd.HasValue && user.LockoutEnd > DateTimeOffset.Now,
                LockoutEnd = user.LockoutEnd,
                CurrentRoles = userRoles.ToList(),
                AvailableRoles = new List<string> { "Admin", "User", "Manager", "HR", "HR Manager" },
                IsCurrentUser = currentUser?.Id == user.Id,
                SecurityStamp = user.SecurityStamp
            };

            return View(model);
        }

        // POST method for handling Edit User form submission
        [HttpPost]
        public async Task<IActionResult> EditUser(EditUserViewModel model)
        {
            if (!ModelState.IsValid)
            {
                // Reload available roles if validation fails
                model.AvailableRoles = new List<string> { "Admin", "User", "Manager", "HR", "HR Manager" };
                return View(model);
            }

            var user = await _userManager.FindByIdAsync(model.Id);
            if (user == null)
            {
                return NotFound();
            }

            var currentUser = await _userManager.GetUserAsync(User);
            
            // Check if user is admin OR editing their own profile
            if (!User.IsInRole("Admin") && currentUser?.Id != model.Id)
            {
                return Forbid(); // Not admin and not own profile
            }

            // Update basic user properties
            user.UserName = model.UserName;
            user.PhoneNumber = model.PhoneNumber;
            
            bool emailChanged = user.Email != model.Email;
            if (emailChanged)
            {
                user.Email = model.Email;
                user.EmailConfirmed = model.EmailConfirmed;
            }
            else
            {
                user.EmailConfirmed = model.EmailConfirmed;
            }

            // Handle lockout
            if (User.IsInRole("Admin"))
            {
                if (model.IsLockedOut && (!user.LockoutEnd.HasValue || user.LockoutEnd <= DateTimeOffset.Now))
                {
                    user.LockoutEnd = DateTimeOffset.Now.AddYears(1);
                }
                else if (!model.IsLockedOut && user.LockoutEnd.HasValue && user.LockoutEnd > DateTimeOffset.Now)
                {
                    user.LockoutEnd = null;
                }
            }

            var result = await _userManager.UpdateAsync(user);
            
            if (result.Succeeded)
            {
                // Handle role changes
                if (User.IsInRole("Admin") && !string.IsNullOrEmpty(model.Role))
                {
                    var currentRoles = await _userManager.GetRolesAsync(user);
                    
                    // Only change roles if the new role is different from current roles
                    if (!currentRoles.Contains(model.Role))
                    {
                        // Remove all current roles
                        if (currentRoles.Any())
                        {
                            await _userManager.RemoveFromRolesAsync(user, currentRoles);
                        }
                        
                        // Add the new primary role
                        await _userManager.AddToRoleAsync(user, model.Role);
                        Console.WriteLine($"Role updated: {model.Role} for user {user.UserName}");
                    }
                }
                
                Console.WriteLine($"User updated successfully: {user.UserName}, Phone: {user.PhoneNumber ?? "NULL"}");
                TempData["SuccessMessage"] = $"User '{model.UserName}' updated successfully!";
                
                // Redirect appropriately
                if (User.IsInRole("Admin"))
                {
                    return RedirectToAction("UserList");
                }
                else
                {
                    return RedirectToAction("Index", "Profile"); // Regular users go back to profile
                }
            }
            
            // If we got this far, something failed
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
                Console.WriteLine($"Update error: {error.Description}");
            }
            
            // Reload available roles if update fails
            model.AvailableRoles = new List<string> { "Admin", "User", "Manager", "HR", "HR Manager" };
            return View(model);
        }

        // POST method for handling user deletion 
        [HttpPost]
        [Authorize(Roles = "Admin")] // Only admins can delete users 
        public async Task<IActionResult> DeleteUser(string id)
        {
            var user = await _userManager.FindByIdAsync(id);
            if (user == null)
            {
                TempData["ErrorMessage"] = "User not found.";
                return RedirectToAction("UserList"); // Redirect back to User List
            }

            var result = await _userManager.DeleteAsync(user);
            if (result.Succeeded)
            {
                TempData["SuccessMessage"] = "User deleted successfully!";
            }
            else
            {
                TempData["ErrorMessage"] = "Failed to delete user.";
            }

            return RedirectToAction("UserList"); // Redirect to the User List page
        }
    }
}