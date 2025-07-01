using Microsoft.AspNetCore.Authorization;

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
}