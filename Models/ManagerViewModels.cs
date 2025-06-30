using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;

namespace AuthenticationApp.Models
{
    public class ManagerDashboardViewModel
    {
        public string CurrentUser { get; set; } = string.Empty;
        public int TotalUsers { get; set; }
        public int ActiveUsers { get; set; }
        public int TotalRoles { get; set; }
        public List<UserSummaryViewModel> RecentUsers { get; set; } = new List<UserSummaryViewModel>();
        public Dictionary<string, int> RoleDistribution { get; set; } = new Dictionary<string, int>();
    }

    public class TeamMemberViewModel
    {
        public string Id { get; set; } = string.Empty;
        public string? UserName { get; set; }
        public string? Email { get; set; }
        public bool EmailConfirmed { get; set; }
        public bool IsLockedOut { get; set; }
        public List<string> Roles { get; set; } = new List<string>();
    }

    public class UserRoleManagementViewModel
    {
        public string UserId { get; set; } = string.Empty;
        public string? UserName { get; set; }
        public string? Email { get; set; }
        public List<string> CurrentRoles { get; set; } = new List<string>();
        public List<string> AvailableRoles { get; set; } = new List<string>();
    }

    public class ManagerReportsViewModel
    {
        public int TotalUsers { get; set; }
        public int ActiveUsers { get; set; }
        public int LockedUsers { get; set; }
        public int UnverifiedUsers { get; set; }
        public List<IdentityUser> RecentRegistrations { get; set; } = new List<IdentityUser>();
    }
}