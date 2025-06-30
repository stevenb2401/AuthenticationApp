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

            _logger.LogDebug("User has roles: {Roles}", string.Join(", ", userRoles));
            _logger.LogDebug("Required roles: {RequiredRoles}", string.Join(", ", requirement.RequiredRoles));

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

    /// <summary>
    /// Handler for tenant-based authorization
    /// </summary>
    public class TenantAuthorizationHandler : AuthorizationHandler<TenantRequirement>
    {
        private readonly ILogger<TenantAuthorizationHandler> _logger;

        public TenantAuthorizationHandler(ILogger<TenantAuthorizationHandler> logger)
        {
            _logger = logger;
        }

        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, TenantRequirement requirement)
        {
            var userTenantId = context.User.FindFirst("tid")?.Value;

            _logger.LogDebug("User tenant ID: {UserTenantId}, Required: {RequiredTenantId}", 
                userTenantId, requirement.RequiredTenantId);

            if (string.Equals(userTenantId, requirement.RequiredTenantId, StringComparison.OrdinalIgnoreCase))
            {
                context.Succeed(requirement);
                _logger.LogInformation("User authorized: correct tenant");
            }
            else
            {
                _logger.LogWarning("User denied: incorrect tenant. User: {UserTenant}, Required: {RequiredTenant}", 
                    userTenantId, requirement.RequiredTenantId);
            }

            return Task.CompletedTask;
        }
    }

    /// <summary>
    /// Handler for claim-based authorization
    /// </summary>
    public class ClaimAuthorizationHandler : AuthorizationHandler<ClaimRequirement>
    {
        private readonly ILogger<ClaimAuthorizationHandler> _logger;

        public ClaimAuthorizationHandler(ILogger<ClaimAuthorizationHandler> logger)
        {
            _logger = logger;
        }

        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, ClaimRequirement requirement)
        {
            var claimValue = context.User.FindFirst(requirement.ClaimType)?.Value;

            _logger.LogDebug("Checking claim {ClaimType} with value {ClaimValue}", 
                requirement.ClaimType, claimValue);

            if (claimValue != null && requirement.AllowedValues.Contains(claimValue, StringComparer.OrdinalIgnoreCase))
            {
                context.Succeed(requirement);
                _logger.LogInformation("User authorized: valid claim value");
            }
            else
            {
                _logger.LogWarning("User denied: claim {ClaimType} value {ClaimValue} not in allowed values", 
                    requirement.ClaimType, claimValue);
            }

            return Task.CompletedTask;
        }
    }

    /// <summary>
    /// Handler for department-based authorization
    /// </summary>
    public class DepartmentAuthorizationHandler : AuthorizationHandler<DepartmentRequirement>
    {
        private readonly ILogger<DepartmentAuthorizationHandler> _logger;

        public DepartmentAuthorizationHandler(ILogger<DepartmentAuthorizationHandler> logger)
        {
            _logger = logger;
        }

        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, DepartmentRequirement requirement)
        {
            var userDepartment = context.User.FindFirst("department")?.Value ?? 
                                context.User.FindFirst("extension_Department")?.Value;

            _logger.LogDebug("User department: {Department}", userDepartment);

            if (userDepartment != null && 
                requirement.AllowedDepartments.Contains(userDepartment, StringComparer.OrdinalIgnoreCase))
            {
                context.Succeed(requirement);
                _logger.LogInformation("User authorized: valid department");
            }
            else
            {
                _logger.LogWarning("User denied: department {Department} not in allowed list", userDepartment);
            }

            return Task.CompletedTask;
        }
    }

    /// <summary>
    /// Handler for business hours authorization
    /// </summary>
    public class BusinessHoursAuthorizationHandler : AuthorizationHandler<BusinessHoursRequirement>
    {
        private readonly ILogger<BusinessHoursAuthorizationHandler> _logger;

        public BusinessHoursAuthorizationHandler(ILogger<BusinessHoursAuthorizationHandler> logger)
        {
            _logger = logger;
        }

        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, BusinessHoursRequirement requirement)
        {
            var now = DateTime.Now;
            var currentTime = now.TimeOfDay;
            var currentDay = now.DayOfWeek;

            _logger.LogDebug("Current time: {Time}, Day: {Day}", currentTime, currentDay);

            var isValidDay = requirement.AllowedDays.Contains(currentDay);
            var isValidTime = currentTime >= requirement.StartTime && currentTime <= requirement.EndTime;

            if (isValidDay && isValidTime)
            {
                context.Succeed(requirement);
                _logger.LogInformation("User authorized: within business hours");
            }
            else
            {
                _logger.LogWarning("User denied: outside business hours. Day valid: {DayValid}, Time valid: {TimeValid}", 
                    isValidDay, isValidTime);
            }

            return Task.CompletedTask;
        }
    }
}