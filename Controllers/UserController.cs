using Authentication_App.Models; // Add this to reference your ViewModels
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace Authentication_App.Controllers
{
    [Authorize(Roles = "Admin")] // Ensure the entire controller is accessible only to admins
    public class UserController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;

        public UserController(UserManager<IdentityUser> userManager)
        {
            _userManager = userManager;
        }

        // GET method for rendering the Create User form
        [HttpGet]
        public IActionResult CreateUser()
        {
            return View(new CreateUserViewModel());
        }

        // POST method for handling Create User form submission
        [HttpPost]
        public async Task<IActionResult> CreateUser(CreateUserViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model); // Return the form with validation errors
            }

            var user = new IdentityUser
            {
                UserName = model.Email,
                Email = model.Email,
                EmailConfirmed = true
            };

            var result = await _userManager.CreateAsync(user, model.Password);
            if (result.Succeeded)
            {
                if (!string.IsNullOrEmpty(model.Role))
                {
                    await _userManager.AddToRoleAsync(user, model.Role);
                }

                TempData["SuccessMessage"] = $"User {model.Email} created successfully!";
                return RedirectToAction("UserList"); // Redirect to the User List page
            }

            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }

            return View(model); // Redisplay the form with errors
        }

        // GET method for displaying the User List
        public IActionResult UserList()
        {
            var users = _userManager.Users.ToList();
            return View(users); // Pass the list of users to the UserList view
        }

        // GET method for rendering the Edit User form
        [HttpGet]
        public async Task<IActionResult> EditUser(string id)
        {
            var user = await _userManager.FindByIdAsync(id);
            if (user == null)
            {
                return NotFound(); // Return 404 if the user doesn't exist
            }

            var model = new EditUserViewModel
            {
                Email = user.Email ?? string.Empty,
                Role = (await _userManager.GetRolesAsync(user)).FirstOrDefault() ?? string.Empty // Default to an empty string
            };

            return View(model);
        }

        // POST method for handling Edit User form submission
        [HttpPost]
        public async Task<IActionResult> EditUser(EditUserViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
            {
                return NotFound();
            }

            // Use a default value to avoid null reference warnings
            var currentRole = (await _userManager.GetRolesAsync(user)).FirstOrDefault() ?? string.Empty;

            if (!string.IsNullOrEmpty(currentRole) && currentRole != model.Role)
            {
                await _userManager.RemoveFromRoleAsync(user, currentRole);
            }
            await _userManager.AddToRoleAsync(user, model.Role);

            TempData["SuccessMessage"] = "User updated successfully!";
            return RedirectToAction("UserList");
        }

        // POST method for handling user deletion
        [HttpPost]
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
