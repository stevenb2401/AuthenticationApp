using Microsoft.AspNetCore.Authorization;

namespace AuthenticationApp.Models
{
    /// Requirement for users with specific roles
    public class RoleRequirement : IAuthorizationRequirement
    {
        public string[] RequiredRoles { get; }
        public bool RequireAllRoles { get; }

        public RoleRequirement(string[] requiredRoles, bool requireAllRoles = false)
        {
            RequiredRoles = requiredRoles ?? throw new ArgumentNullException(nameof(requiredRoles));
            RequireAllRoles = requireAllRoles;
        }
    }

    public class BusinessHoursRequirement : IAuthorizationRequirement
    {
        public TimeSpan StartTime { get; }
        public TimeSpan EndTime { get; }
        public DayOfWeek[] AllowedDays { get; }

        public BusinessHoursRequirement(TimeSpan startTime, TimeSpan endTime, params DayOfWeek[] allowedDays)
        {
            StartTime = startTime;
            EndTime = endTime;
            AllowedDays = allowedDays ?? new[] { DayOfWeek.Monday, DayOfWeek.Tuesday, DayOfWeek.Wednesday, DayOfWeek.Thursday, DayOfWeek.Friday };
        }
    }

    public class TenantRequirement : IAuthorizationRequirement
    {
        public string RequiredTenantId { get; }

        public TenantRequirement(string requiredTenantId)
        {
            RequiredTenantId = requiredTenantId ?? throw new ArgumentNullException(nameof(requiredTenantId));
        }
    }
}    