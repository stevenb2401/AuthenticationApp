using Microsoft.AspNetCore.Authorization;
using AuthenticationApp.Models;
using System.Security.Claims;
using Microsoft.AspNetCore.Identity;

namespace AuthenticationApp.Services
{
    public class RoleAuthorizationHandler : AuthorizationHandler<RoleRequirement>
    {
        private readonly ILogger<RoleAuthorizationHandler> _logger;
        private readonly UserManager<IdentityUser> _userManager;

        public RoleAuthorizationHandler(ILogger<RoleAuthorizationHandler> logger, UserManager<IdentityUser> userManager)
        {
            _logger = logger;
            _userManager = userManager;
        }

        protected override async Task HandleRequirementAsync(AuthorizationHandlerContext context, RoleRequirement requirement)
        {
            try
            {
                var azureAdRoles = context.User.FindAll("roles")
                    .Union(context.User.FindAll(ClaimTypes.Role))
                    .Union(context.User.FindAll("groups"))
                    .Select(c => c.Value)
                    .ToList();

                _logger.LogDebug("Azure AD roles from claims: {AzureAdRoles}", string.Join(", ", azureAdRoles));

                var localRoles = new List<string>();
                var userEmail = context.User.FindFirst(ClaimTypes.Email)?.Value ?? 
                               context.User.FindFirst("preferred_username")?.Value;

                _logger.LogDebug("Looking up local roles for email: {Email}", userEmail ?? "NULL");

                if (!string.IsNullOrEmpty(userEmail))
                {
                    try
                    {
                        var localUser = await _userManager.FindByEmailAsync(userEmail);
                        if (localUser != null)
                        {
                            _logger.LogDebug("Found local user with ID: {UserId}", localUser.Id);
                            var userLocalRoles = await _userManager.GetRolesAsync(localUser);
                            localRoles.AddRange(userLocalRoles);
                            _logger.LogDebug("Local Identity roles for {Email}: {LocalRoles}", userEmail, string.Join(", ", localRoles));
                        }
                        else
                        {
                            _logger.LogWarning("No local user found for email: {Email}", userEmail);
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Error looking up local user for email: {Email}", userEmail);
                    }
                }
                else
                {
                    _logger.LogWarning("No email claim found in user context");
                }

                var allUserRoles = azureAdRoles.Union(localRoles).Distinct().ToList();

                _logger.LogDebug("Combined user roles: {UserRoles}, Required: {RequiredRoles}", 
                    string.Join(", ", allUserRoles), string.Join(", ", requirement.RequiredRoles));

                if (requirement.RequireAllRoles)
                {
                    if (requirement.RequiredRoles.All(role => allUserRoles.Contains(role, StringComparer.OrdinalIgnoreCase)))
                    {
                        context.Succeed(requirement);
                        _logger.LogInformation("User authorised: has all required roles");
                        return;
                    }
                    else
                    {
                        _logger.LogWarning("User denied: missing required roles");
                    }
                }
                else
                {
                    if (requirement.RequiredRoles.Any(role => allUserRoles.Contains(role, StringComparer.OrdinalIgnoreCase)))
                    {
                        context.Succeed(requirement);
                        _logger.LogInformation("User authorised: has at least one required role");
                        return;
                    }
                    else
                    {
                        _logger.LogWarning("User denied: no matching roles found");
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in role authorisation handler");
            }

            context.Fail();
        }
    }
}