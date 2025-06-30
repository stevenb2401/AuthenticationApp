using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;

namespace AuthenticationApp.Models
{
    /// <summary>
    /// Requirement for users with specific roles
    /// </summary>
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

    /// <summary>
    /// Requirement for users from specific tenant
    /// </summary>
    public class TenantRequirement : IAuthorizationRequirement
    {
        public string RequiredTenantId { get; }

        public TenantRequirement(string requiredTenantId)
        {
            RequiredTenantId = requiredTenantId ?? throw new ArgumentNullException(nameof(requiredTenantId));
        }
    }

    /// <summary>
    /// Requirement for users with specific claims
    /// </summary>
    public class ClaimRequirement : IAuthorizationRequirement
    {
        public string ClaimType { get; }
        public string[] AllowedValues { get; }

        public ClaimRequirement(string claimType, params string[] allowedValues)
        {
            ClaimType = claimType ?? throw new ArgumentNullException(nameof(claimType));
            AllowedValues = allowedValues ?? throw new ArgumentNullException(nameof(allowedValues));
        }
    }

    /// <summary>
    /// Requirement for department-based access
    /// </summary>
    public class DepartmentRequirement : IAuthorizationRequirement
    {
        public string[] AllowedDepartments { get; }

        public DepartmentRequirement(params string[] allowedDepartments)
        {
            AllowedDepartments = allowedDepartments ?? throw new ArgumentNullException(nameof(allowedDepartments));
        }
    }

    /// <summary>
    /// Time-based access requirement (business hours)
    /// </summary>
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
}