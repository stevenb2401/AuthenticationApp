namespace Authentication_App.Models
{
    public class UserStatisticsViewModel
    {
        public int TotalUsers { get; set; }
        public int ActiveUsers { get; set; }
        public int LockedUsers { get; set; }
        public Dictionary<string, int> RoleDistribution { get; set; } = new Dictionary<string, int>();
    }
}
