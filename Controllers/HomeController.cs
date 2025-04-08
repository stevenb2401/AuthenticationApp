using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using Authentication_App.Models;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;

namespace Authentication_App.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;

        public HomeController(ILogger<HomeController> logger)
        {
            _logger = logger;
        }

        // Updated Index action with ViewData["Title"] initialization
        public IActionResult Index()
        {
            ViewData["Title"] = "Home Page"; // Set the page title for layout
            return View(); // Return the Index.cshtml view
        }

        [Authorize]
        public IActionResult Privacy()
        {
            // Retrieve and pass some user claims to the view
            var userName = User.Identity?.Name ?? "Unknown";
            var email = User.FindFirst(ClaimTypes.Email)?.Value ?? "Email not available";

            ViewData["UserName"] = userName;
            ViewData["Email"] = email;

            return View(); // Return the Privacy.cshtml view
        }

        // Logout action to sign out the user
        [HttpGet("logout")]
        public IActionResult Logout()
        {
            return SignOut(
                new AuthenticationProperties { RedirectUri = "/" },
                CookieAuthenticationDefaults.AuthenticationScheme,
                OpenIdConnectDefaults.AuthenticationScheme);
        }

        // Error handling action
        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel
            {
                RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier
            });
        }
    }
}
