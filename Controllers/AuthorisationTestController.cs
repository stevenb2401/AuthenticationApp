using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AuthenticationApp.Controllers
{
    [Authorize]
    public class AuthorisationTestController : Controller
    {
        private readonly ILogger<AuthorisationTestController> _logger;
        private readonly IAuthorizationService _authorizationService;

        public AuthorisationTestController(ILogger<AuthorisationTestController> logger, IAuthorizationService authorizationService)
        {
            _logger = logger;
            _authorizationService = authorizationService;
        }

        /// <summary>
        /// Shows authorisation test dashboard
        /// </summary>
        public async Task<IActionResult> Index()
        {
            _logger.LogInformation("Authorisation test dashboard accessed by user: {User}", User.Identity?.Name);

            // Fixed policy names to match your actual Program.cs configuration
            var policies = new[]
            {
                "Admin", "Manager_or_Admin", "HR_Access",  
                "Local_Admin", "Local_User"
            };

            var policyResults = new Dictionary<string, bool>();

            foreach (var policy in policies)
            {
                try
                {
                    var result = await _authorizationService.AuthorizeAsync(User, policy);
                    policyResults[policy] = result.Succeeded;
                    
                    _logger.LogDebug("Policy {Policy}: {Result}", policy, result.Succeeded ? "AUTHORISED" : "DENIED");
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error evaluating policy {Policy}", policy);
                    policyResults[policy] = false;
                }
            }

            ViewBag.PolicyResults = policyResults;
            ViewBag.CurrentTime = DateTime.Now;
            ViewBag.IsBusinessHours = IsCurrentlyBusinessHours();
            
            return View();
        }

        [Authorize(Policy = "Admin")]
        public IActionResult AdminOnly()
        {
            _logger.LogInformation("Admin only page accessed by user: {User}", User.Identity?.Name);
            return View();
        }

        [Authorize(Policy = "Manager_or_Admin")]
        public IActionResult ManagerOrAdmin()
        {
            _logger.LogInformation("Manager or Admin page accessed by user: {User}", User.Identity?.Name);
            return View();
        }

        [Authorize(Policy = "BusinessHours")]
        public IActionResult BusinessHours()
        {
            _logger.LogInformation("Business hours page accessed by user: {User} at {Time}", 
                User.Identity?.Name, DateTime.Now);
            return View();
        }

        [Authorize(Policy = "IT_Department")]
        public IActionResult ITDepartment()
        {
            _logger.LogInformation("IT Department page accessed by user: {User}", User.Identity?.Name);
            return View();
        }

        [Authorize(Policy = "AdminBusinessHours")]
        public IActionResult AdminBusinessHours()
        {
            _logger.LogInformation("Admin Business Hours page accessed by user: {User} at {Time}", 
                User.Identity?.Name, DateTime.Now);
            return View();
        }

        [Authorize(Policy = "Local_Admin")]
        public IActionResult LocalAdminOnly()
        {
            _logger.LogInformation("Local Admin only page accessed by user: {User}", User.Identity?.Name);
            return View();
        }

        /// <summary>
        /// Test page that shows policy evaluation results
        /// </summary>
        public async Task<IActionResult> PolicyTest(string policyName)
        {
            if (string.IsNullOrEmpty(policyName))
            {
                return BadRequest("Policy name is required");
            }

            try
            {
                var result = await _authorizationService.AuthorizeAsync(User, policyName);
                
                ViewBag.PolicyName = policyName;
                ViewBag.IsAuthorised = result.Succeeded;
                ViewBag.FailureReasons = result.Failure?.FailureReasons?.Select(r => r.Message) ?? new List<string>();
                
                _logger.LogInformation("Policy test for {Policy}: {Result}", policyName, result.Succeeded);
                
                return View();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error testing policy {Policy}", policyName);
                ViewBag.Error = $"Error testing policy: {ex.Message}";
                return View();
            }
        }

        /// <summary>
        /// Shows detailed user claims for debugging
        /// </summary>
        public IActionResult UserInfo()
        {
            var userInfo = new
            {
                Name = User.Identity?.Name,
                IsAuthenticated = User.Identity?.IsAuthenticated,
                AuthenticationType = User.Identity?.AuthenticationType,
                Claims = User.Claims.Select(c => new { c.Type, c.Value, c.Issuer }).ToList(),
                Roles = User.FindAll("roles")
                    .Union(User.FindAll(System.Security.Claims.ClaimTypes.Role))
                    .Union(User.FindAll("groups"))
                    .Select(c => c.Value)
                    .Distinct()
                    .ToList(),
                Department = User.FindFirst("department")?.Value ?? 
                           User.FindFirst("extension_Department")?.Value ?? "Not specified",
                TenantId = User.FindFirst("tid")?.Value ?? "Not found",
                ObjectId = User.FindFirst("oid")?.Value ?? "Not found"
            };

            ViewBag.UserInfo = userInfo;
            return View();
        }

        /// <summary>
        /// Helper method to check if current time is within business hours
        /// </summary>
        private bool IsCurrentlyBusinessHours()
        {
            var now = DateTime.Now;
            var currentTime = now.TimeOfDay;
            var currentDay = now.DayOfWeek;

            var businessDays = new[] { DayOfWeek.Monday, DayOfWeek.Tuesday, DayOfWeek.Wednesday, DayOfWeek.Thursday, DayOfWeek.Friday };
            var startTime = new TimeSpan(9, 0, 0); // 9:00 AM
            var endTime = new TimeSpan(17, 0, 0);  // 5:00 PM

            return businessDays.Contains(currentDay) && 
                   currentTime >= startTime && 
                   currentTime <= endTime;
        }

        /// <summary>
        /// API endpoint to check authorisation for a specific policy
        /// </summary>
        [HttpGet]
        public async Task<IActionResult> CheckPolicy(string policy)
        {
            if (string.IsNullOrEmpty(policy))
            {
                return Json(new { success = false, message = "Policy name is required" });
            }

            try
            {
                var result = await _authorizationService.AuthorizeAsync(User, policy);
                
                return Json(new 
                { 
                    success = true, 
                    policy = policy,
                    authorised = result.Succeeded,
                    user = User.Identity?.Name,
                    timestamp = DateTime.Now
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error checking policy {Policy}", policy);
                return Json(new { success = false, message = ex.Message });
            }
        }
    }
}