using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace AuthenticationApp.Controllers
{
    public class TestController : Controller
    {
        private readonly ILogger<TestController> _logger;

        public TestController(ILogger<TestController> logger)
        {
            _logger = logger;
        }

        [HttpGet("/test-auth")]
        public IActionResult TestAuth()
        {
            _logger.LogInformation("🧪 Test auth endpoint called");
            
            var props = new AuthenticationProperties
            {
                RedirectUri = Url.Action("TestCallback"),
                Items = { { "scheme", OpenIdConnectDefaults.AuthenticationScheme } }
            };

            _logger.LogInformation("🚀 Challenging with OpenIdConnect scheme");
            return Challenge(props, OpenIdConnectDefaults.AuthenticationScheme);
        }

        [HttpGet("/test-callback")]
        public async Task<IActionResult> TestCallback()
        {
            _logger.LogInformation("🎯 Test callback reached");
            _logger.LogInformation("🔐 Is authenticated: {IsAuth}", User?.Identity?.IsAuthenticated);
            _logger.LogInformation("👤 User: {User}", User?.Identity?.Name);
            
            // Log all claims
            if (User?.Identity?.IsAuthenticated == true)
            {
                foreach (var claim in User.Claims)
                {
                    _logger.LogInformation("🏷️ Claim: {Type} = {Value}", claim.Type, claim.Value);
                }
            }

            return View("TestResult");
        }

        [HttpGet("/test-signout")]
        public async Task<IActionResult> TestSignout()
        {
            _logger.LogInformation("🚪 Test signout called");
            
            await HttpContext.SignOutAsync();
            return RedirectToAction("Index", "Home");
        }
        
        [HttpGet("/test-status")]
        public IActionResult TestStatus()
        {
            var status = new
            {
                IsAuthenticated = User?.Identity?.IsAuthenticated ?? false,
                Name = User?.Identity?.Name,
                AuthenticationType = User?.Identity?.AuthenticationType,
                Claims = User?.Claims?.Select(c => new { c.Type, c.Value }).ToList(),
                Schemes = HttpContext.RequestServices.GetRequiredService<IAuthenticationSchemeProvider>()
                    .GetAllSchemesAsync().Result.Select(s => s.Name).ToList()
            };
            
            return Json(status);
        }
    }
}