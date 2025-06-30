using System.ComponentModel.DataAnnotations;

namespace AuthenticationApp.Models
{
    public class UserProfileViewModel
    {
        [Display(Name = "Display Name")]
        public string DisplayName { get; set; } = string.Empty;

        [Display(Name = "Email Address")]
        [EmailAddress]
        public string Email { get; set; } = string.Empty;

        [Display(Name = "Username")]
        public string Name { get; set; } = string.Empty;

        [Display(Name = "Job Title")]
        public string JobTitle { get; set; } = string.Empty;

        [Display(Name = "Department")]
        public string Department { get; set; } = string.Empty;

        [Display(Name = "User Roles")]
        public List<string> Roles { get; set; } = new List<string>();

        [Display(Name = "Authentication Status")]
        public bool IsAuthenticated { get; set; }

        [Display(Name = "User ID")]
        public string ObjectId { get; set; } = string.Empty;

        [Display(Name = "Tenant ID")]
        public string TenantId { get; set; } = string.Empty;

        [Display(Name = "Phone Number")]
        public string PhoneNumber { get; set; } = string.Empty;

        [Display(Name = "Office Location")]
        public string OfficeLocation { get; set; } = string.Empty;

        [Display(Name = "Manager")]
        public string Manager { get; set; } = string.Empty;

        // Helper properties for UI display
        public string RolesDisplay => Roles.Any() ? string.Join(", ", Roles) : "No roles assigned";
        
        public string AuthenticationStatusDisplay => IsAuthenticated ? "Authenticated" : "Not Authenticated";
        
        public bool HasAdminRole => Roles.Contains("Admin", StringComparer.OrdinalIgnoreCase);
        
        public bool HasManagerRole => Roles.Contains("Manager", StringComparer.OrdinalIgnoreCase);
    }
}