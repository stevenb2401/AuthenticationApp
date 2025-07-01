using Microsoft.AspNetCore.Authorization;
using AuthenticationApp.Models;
using System.Security.Claims;

namespace AuthenticationApp.Services
{
    /// <summary>
    /// Handler for role-based authorization
    /// </summary>
    public class RoleAuthorizationHandler : AuthorizationHandler<RoleRequirement>
    {
        private readonly ILogger<RoleAuthorizationHandler> _logger;

        public RoleAuthorizationHandler(ILogger<RoleAuthorizationHandler> logger)
        {
            _logger = logger;
        }

        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, RoleRequirement requirement)
        {
            var userRoles = context.User.FindAll("roles")
                .Union(context.User.FindAll(ClaimTypes.Role))
                .Union(context.User.FindAll("groups"))
                .Select(c => c.Value)
                .ToList();

            _logger.LogDebug("User has roles: {UserRoles}, Required: {RequiredRoles}", 
                string.Join(", ", userRoles), string.Join(", ", requirement.RequiredRoles));

            if (requirement.RequireAllRoles)
            {
                // User must have ALL required roles
                if (requirement.RequiredRoles.All(role => userRoles.Contains(role, StringComparer.OrdinalIgnoreCase)))
                {
                    context.Succeed(requirement);
                    _logger.LogInformation("User authorized: has all required roles");
                }
                else
                {
                    _logger.LogWarning("User denied: missing required roles");
                }
            }
            else
            {
                // User must have AT LEAST ONE required role
                if (requirement.RequiredRoles.Any(role => userRoles.Contains(role, StringComparer.OrdinalIgnoreCase)))
                {
                    context.Succeed(requirement);
                    _logger.LogInformation("User authorized: has at least one required role");
                }
                else
                {
                    _logger.LogWarning("User denied: no matching roles found");
                }
            }

            return Task.CompletedTask;
        }
    }
}