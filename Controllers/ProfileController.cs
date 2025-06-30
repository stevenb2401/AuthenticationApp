using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using AuthenticationApp.Models;
using System.Security.Claims;

namespace AuthenticationApp.Controllers
{
    [Authorize]
    public class ProfileController : Controller
    {
        private readonly ILogger<ProfileController> _logger;

        public ProfileController(ILogger<ProfileController> logger)
        {
            _logger = logger;
        }

/// <summary>
/// Default profile page - provides overview and navigation to detailed views
/// </summary>
        public IActionResult Index()
        {
            try
            {
                // Get basic user info for the overview
                var userInfo = new
                {
                    DisplayName = User.FindFirst("name")?.Value ?? User.Identity?.Name ?? "Unknown User",
                    Email = GetClaimValue("preferred_username") ?? GetClaimValue("email") ?? "No email found",
                    IsAuthenticated = User.Identity?.IsAuthenticated ?? false,
                    UserId = GetClaimValue("oid") ?? "No ID found",
                    RoleCount = ExtractRolesFromClaims().Count,
                    ClaimsCount = User.Claims.Count()
                };

                _logger.LogInformation("User {UserId} accessed profile overview", userInfo.UserId);
        
                ViewBag.UserInfo = userInfo;
                return View();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error loading profile overview");
                ViewBag.Error = "Unable to load profile overview. Please try again.";
                return View();
            }
        }

        /// <summary>
        /// Displays the user's profile information extracted from Azure AD claims
        /// </summary>
        public IActionResult Details()
        {
            try
            {
                // Extract user information from claims
                var model = ExtractUserProfileFromClaims();

                // Log the successful profile access
                _logger.LogInformation("User {UserId} accessed their profile", model.ObjectId);

                return View(model);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error loading user profile");

                // Return a model with error information
                var errorModel = new UserProfileViewModel
                {
                    Name = "Error loading profile",
                    IsAuthenticated = User.Identity?.IsAuthenticated ?? false
                };

                ViewBag.Error = "Unable to load profile information. Please try again.";
                return View(errorModel);
            }
        }

        /// <summary>
        /// Extracts user profile information from Azure AD claims
        /// </summary>
        private UserProfileViewModel ExtractUserProfileFromClaims()
        {
            var model = new UserProfileViewModel();

            // Basic identity information
            model.Name = User.Identity?.Name ?? "Unknown User";
            model.IsAuthenticated = User.Identity?.IsAuthenticated ?? false;

            // Azure AD specific claims
            model.Email = GetClaimValue("preferred_username") ?? 
                         GetClaimValue("email") ?? 
                         GetClaimValue("upn") ?? 
                         "No email found";

            model.DisplayName = GetClaimValue("name") ?? 
                               GetClaimValue("given_name") + " " + GetClaimValue("family_name") ?? 
                               model.Name;

            model.ObjectId = GetClaimValue("oid") ?? GetClaimValue("sub") ?? "No ID found";
            model.TenantId = GetClaimValue("tid") ?? "No tenant found";

            // Extended profile information
            model.JobTitle = GetClaimValue("jobTitle") ?? GetClaimValue("extension_JobTitle") ?? "";
            model.Department = GetClaimValue("department") ?? GetClaimValue("extension_Department") ?? "";
            model.PhoneNumber = GetClaimValue("phone_number") ?? GetClaimValue("mobile_phone") ?? "";
            model.OfficeLocation = GetClaimValue("office_location") ?? "";
            model.Manager = GetClaimValue("manager") ?? "";

            // Extract roles from claims
            model.Roles = ExtractRolesFromClaims();

            // Log the claims extraction for debugging
            _logger.LogDebug("Extracted profile for user {ObjectId}: {DisplayName}", 
                model.ObjectId, model.DisplayName);

            return model;
        }

        /// <summary>
        /// Helper method to get claim value safely
        /// </summary>
        private string? GetClaimValue(string claimType)
        {
            return User.FindFirst(claimType)?.Value;
        }

        /// <summary>
        /// Extracts user roles from various possible claim types
        /// </summary>
        private List<string> ExtractRolesFromClaims()
        {
            var roles = new List<string>();

            // Check multiple possible role claim types
            var roleClaims = User.FindAll("roles")?.Select(c => c.Value) ?? new List<string>();
            roles.AddRange(roleClaims);

            // Also check standard role claim type
            var standardRoles = User.FindAll(ClaimTypes.Role)?.Select(c => c.Value) ?? new List<string>();
            roles.AddRange(standardRoles);

            // Check group claims
            var groupClaims = User.FindAll("groups")?.Select(c => c.Value) ?? new List<string>();
            roles.AddRange(groupClaims);

            // Remove duplicates and return
            return roles.Distinct().ToList();
        }

        /// <summary>
        /// Returns detailed claims information for debugging
        /// </summary>
        public IActionResult Claims()
        {
            var claims = User.Claims.Select(c => new 
            { 
                Type = c.Type, 
                Value = c.Value 
            }).ToList();

            ViewBag.Claims = claims;
            return View();
        }

        /// <summary>
        /// Action to display all available claims for debugging
        /// </summary>
        public IActionResult DebugClaims()
        {
            if (!User.Identity?.IsAuthenticated ?? true)
            {
                return Challenge();
            }

            var claimsInfo = User.Claims.Select(claim => new
            {
                Type = claim.Type,
                Value = claim.Value,
                ValueType = claim.ValueType,
                Issuer = claim.Issuer
            }).OrderBy(c => c.Type).ToList();

            ViewBag.ClaimsCount = claimsInfo.Count;
            ViewBag.UserId = GetClaimValue("oid");
            ViewBag.UserEmail = GetClaimValue("preferred_username");

            return View(claimsInfo);
        }
    }
}