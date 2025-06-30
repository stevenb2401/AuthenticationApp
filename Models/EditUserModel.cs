using System.ComponentModel.DataAnnotations;

namespace Authentication_App.Models
{
    public class EditUserViewModel
    {
        // Hidden field for user identification
        public string Id { get; set; } = string.Empty;

        [Required(ErrorMessage = "Username is required.")]
        [Display(Name = "Username/Display Name")]
        public string UserName { get; set; } = string.Empty;

        [Required(ErrorMessage = "Email is required.")]
        [EmailAddress(ErrorMessage = "Invalid email address.")]
        [Display(Name = "Email Address")]
        public string Email { get; set; } = string.Empty;

        [Phone(ErrorMessage = "Invalid phone number.")]
        [Display(Name = "Phone Number")]
        public string? PhoneNumber { get; set; }

        [Required(ErrorMessage = "Role is required.")]
        [Display(Name = "Primary Role")]
        public string Role { get; set; } = string.Empty;

        [Display(Name = "Email Confirmed")]
        public bool EmailConfirmed { get; set; }

        [Display(Name = "Account Locked")]
        public bool IsLockedOut { get; set; }

        [Display(Name = "Lockout End Date")]
        public DateTimeOffset? LockoutEnd { get; set; }

        // Additional role management
        [Display(Name = "All User Roles")]
        public List<string> CurrentRoles { get; set; } = new List<string>();
        
        public List<string> AvailableRoles { get; set; } = new List<string>();

        // Read-only information for display
        public DateTime? CreatedDate { get; set; }
        public DateTime? LastLoginDate { get; set; }
        public bool IsCurrentUser { get; set; }

        // Security timestamp for concurrency
        public string? SecurityStamp { get; set; }
    }
}