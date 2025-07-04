namespace AuthenticationApp.Models
{
    public class UserProfileViewModel
    {
        // Basic Information 
        public string DisplayName { get; set; } = "No display name found";
        public string Email { get; set; } = "No email found";
        public string? PhoneNumber { get; set; } 
        
        public bool IsAuthenticated { get; set; }
        public string AuthenticationStatusDisplay { get; set; } = "Not Authenticated";
        
        public List<string> Roles { get; set; } = new List<string>();
        public bool HasAdminRole { get; set; }
        
        public string ObjectId { get; set; } = "No ID found";
        public string TenantId { get; set; } = "Not available";
        
        public bool EmailConfirmed { get; set; }
        public bool IsLockedOut { get; set; }
        public DateTimeOffset? LockoutEnd { get; set; }
        
        public DateTime? LastLoginDate { get; set; }
        public DateTime? CreatedDate { get; set; }
    }
}