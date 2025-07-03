using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using Authentication_App.Models;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using AuthenticationApp.Services;

namespace Authentication_App.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;
        private readonly IUserActivityService _userActivityService;

        public HomeController(ILogger<HomeController> logger, IUserActivityService userActivityService)
        {
            _logger = logger;
            _userActivityService = userActivityService;
        }

        public IActionResult Index()
        {
            ViewData["Title"] = "Home Page";

            // Track user access to home page
            if (User.Identity?.IsAuthenticated == true)
            {
                var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
                var email = User.FindFirst(ClaimTypes.Email)?.Value;

                _userActivityService.TrackUserAction(userId, "HomePageAccess", new Dictionary<string, string>
                {
                    ["Page"] = "Index",
                    ["UserAgent"] = Request.Headers["User-Agent"].ToString(),
                    ["IPAddress"] = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown"
                });
            }

            return View();
        }

        [Authorize]
        public IActionResult Privacy()
        {
            // Retrieve and pass some user claims to the view
            var userName = User.Identity?.Name ?? "Unknown";
            var email = User.FindFirst(ClaimTypes.Email)?.Value ?? "Email not available";
            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;

            ViewData["UserName"] = userName;
            ViewData["Email"] = email;

            // Track privacy page access
            _userActivityService.TrackUserAction(userId, "PrivacyPageAccess", new Dictionary<string, string>
            {
                ["UserName"] = userName,
                ["Email"] = email
            });

            return View();
        }
    }
}
