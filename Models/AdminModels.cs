namespace AuthenticationApp.Models
{
    public class AdminDashboardViewModel
    {
        public int TotalUsers { get; set; }
        public int TotalRoles { get; set; }
        public List<UserSummaryViewModel> RecentUsers { get; set; } = new List<UserSummaryViewModel>();
        public List<RoleViewModel> SystemRoles { get; set; } = new List<RoleViewModel>();
        public IList<string> CurrentAdminRoles { get; set; } = new List<string>();
    }

    public class UserSummaryViewModel
    {
        public string Id { get; set; } = string.Empty;
        public string UserName { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public bool EmailConfirmed { get; set; }
        public bool LockoutEnabled { get; set; }
        public int AccessFailedCount { get; set; }
    }

    public class RoleViewModel
    {
        public string Id { get; set; } = string.Empty;
        public string Name { get; set; } = string.Empty;
        public string NormalizedName { get; set; } = string.Empty;
    }
}