using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Authentication_App.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authentication;
using Microsoft.EntityFrameworkCore; 

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

        // POST local login
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
                if (model.Email.Contains("@"))
                {
                    user = await _userManager.FindByEmailAsync(model.Email);
                    _logger.LogInformation("Searching by email: {Email}", model.Email);
                }
                else
                {
                    user = await _userManager.FindByNameAsync(model.Email);
                    _logger.LogInformation("Searching by username: {Username}", model.Email);
                }

                if (user != null)
                {
                    _logger.LogInformation("Found user {Email} with username {UserName}", user.Email, user.UserName);

                    var result = await _signInManager.PasswordSignInAsync(
                        user.UserName!,
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

        // Logout
        [HttpGet("logout")]
        public async Task<IActionResult> Logout()
        {
            await _signInManager.SignOutAsync();
            return SignOut(
                new AuthenticationProperties { RedirectUri = "/" },
                OpenIdConnectDefaults.AuthenticationScheme
            );
        }
    }   
}