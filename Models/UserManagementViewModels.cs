using System.ComponentModel.DataAnnotations;

namespace AuthenticationApp.Models
{
    /// View model for creating a new user
    public class CreateUserViewModel
    {
        [Required(ErrorMessage = "Email is required")]
        [EmailAddress(ErrorMessage = "Please enter a valid email address")]
        [Display(Name = "Email Address")]
        public string Email { get; set; } = string.Empty;

        [Required(ErrorMessage = "Username is required")]
        [StringLength(50, MinimumLength = 3, ErrorMessage = "Username must be between 3 and 50 characters")]
        [Display(Name = "Username")]
        public string UserName { get; set; } = string.Empty;

        [Required(ErrorMessage = "Password is required")]
        [StringLength(100, MinimumLength = 8, ErrorMessage = "Password must be at least 8 characters long")]
        [DataType(DataType.Password)]
        [Display(Name = "Password")]
        public string Password { get; set; } = string.Empty;

        [Required(ErrorMessage = "Please confirm your password")]
        [DataType(DataType.Password)]
        [Display(Name = "Confirm Password")]
        [Compare("Password", ErrorMessage = "Password and confirmation password do not match")]
        public string ConfirmPassword { get; set; } = string.Empty;

        [StringLength(100, ErrorMessage = "First name cannot exceed 100 characters")]
        [Display(Name = "First Name")]
        public string FirstName { get; set; } = string.Empty;

        [StringLength(100, ErrorMessage = "Last name cannot exceed 100 characters")]
        [Display(Name = "Last Name")]
        public string LastName { get; set; } = string.Empty;

        [Phone(ErrorMessage = "Please enter a valid phone number")]
        [Display(Name = "Phone Number")]
        public string? PhoneNumber { get; set; }

        [Display(Name = "Account Enabled")]
        public bool IsEnabled { get; set; } = true;

        [Display(Name = "Email Confirmed")]
        public bool EmailConfirmed { get; set; } = false;

        [Display(Name = "Require Password Change")]
        public bool RequirePasswordChange { get; set; } = true;

        [Display(Name = "Selected Roles")]
        public List<string> SelectedRoles { get; set; } = new List<string>();

        public List<RoleSelectionViewModel> AvailableRoles { get; set; } = new List<RoleSelectionViewModel>();
    }

    /// View model for editing an existing user
    public class EditUserViewModel
    {
        public string Id { get; set; } = string.Empty;

        [Required(ErrorMessage = "Email is required")]
        [EmailAddress(ErrorMessage = "Please enter a valid email address")]
        [Display(Name = "Email Address")]
        public string Email { get; set; } = string.Empty;

        [Required(ErrorMessage = "Username is required")]
        [StringLength(50, MinimumLength = 3, ErrorMessage = "Username must be between 3 and 50 characters")]
        [Display(Name = "Username")]
        public string UserName { get; set; } = string.Empty;

        [StringLength(100, ErrorMessage = "First name cannot exceed 100 characters")]
        [Display(Name = "First Name")]
        public string FirstName { get; set; } = string.Empty;

        [StringLength(100, ErrorMessage = "Last name cannot exceed 100 characters")]
        [Display(Name = "Last Name")]
        public string LastName { get; set; } = string.Empty;

        [Phone(ErrorMessage = "Please enter a valid phone number")]
        [Display(Name = "Phone Number")]
        public string? PhoneNumber { get; set; }

        [Display(Name = "Account Enabled")]
        public bool IsEnabled { get; set; }

        [Display(Name = "Email Confirmed")]
        public bool EmailConfirmed { get; set; }

        [Display(Name = "Phone Number Confirmed")]
        public bool PhoneNumberConfirmed { get; set; }

        [Display(Name = "Two Factor Enabled")]
        public bool TwoFactorEnabled { get; set; }

        [Display(Name = "Lockout Enabled")]
        public bool LockoutEnabled { get; set; }

        public DateTimeOffset? LockoutEnd { get; set; }
        public int AccessFailedCount { get; set; }
        public DateTime? LastLoginDate { get; set; }
        public DateTime CreatedDate { get; set; }

        [Display(Name = "User Roles")]
        public List<string> CurrentRoles { get; set; } = new List<string>();

        [Display(Name = "Selected Roles")]
        public List<string> SelectedRoles { get; set; } = new List<string>();

        public List<RoleSelectionViewModel> AvailableRoles { get; set; } = new List<RoleSelectionViewModel>();

        // Security properties
        public bool IsLockedOut => LockoutEnd.HasValue && LockoutEnd > DateTimeOffset.UtcNow;
        public string AccountStatus => IsLockedOut ? "Locked" : IsEnabled ? "Active" : "Disabled";
        public string SecurityStatus
        {
            get
            {
                var status = new List<string>();
                if (IsLockedOut) status.Add("Locked Out");
                if (!EmailConfirmed) status.Add("Email Unverified");
                if (TwoFactorEnabled) status.Add("2FA Enabled");
                if (AccessFailedCount > 0) status.Add($"{AccessFailedCount} Failed Attempts");
                return status.Any() ? string.Join(", ", status) : "Secure";
            }
        }
    }

    /// View model for password reset
    public class ResetPasswordViewModel
    {
        public string UserId { get; set; } = string.Empty;
        public string UserName { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;

        [Required(ErrorMessage = "New password is required")]
        [StringLength(100, MinimumLength = 8, ErrorMessage = "Password must be at least 8 characters long")]
        [DataType(DataType.Password)]
        [Display(Name = "New Password")]
        public string NewPassword { get; set; } = string.Empty;

        [Required(ErrorMessage = "Please confirm the new password")]
        [DataType(DataType.Password)]
        [Display(Name = "Confirm New Password")]
        [Compare("NewPassword", ErrorMessage = "Password and confirmation password do not match")]
        public string ConfirmPassword { get; set; } = string.Empty;

        [Display(Name = "Require Password Change on Next Login")]
        public bool RequirePasswordChange { get; set; } = true;

        [Display(Name = "Send Email Notification")]
        public bool SendEmailNotification { get; set; } = true;
    }

    /// View model for user search and filtering
    public class UserSearchViewModel
    {
        [Display(Name = "Search Term")]
        public string SearchTerm { get; set; } = string.Empty;

        [Display(Name = "Filter by Role")]
        public string? SelectedRole { get; set; }

        [Display(Name = "Account Status")]
        public UserAccountStatus? AccountStatus { get; set; }

        [Display(Name = "Show Locked Accounts Only")]
        public bool ShowLockedOnly { get; set; }

        [Display(Name = "Show Unverified Email Only")]
        public bool ShowUnverifiedOnly { get; set; }

        public List<UserSearchResultViewModel> Results { get; set; } = new List<UserSearchResultViewModel>();
        public List<string> AvailableRoles { get; set; } = new List<string>();

        public List<string> AvailableDepartments { get; set; } = new List<string>();
        
        public int TotalResults { get; set; }
        public int CurrentPage { get; set; } = 1;
        public int PageSize { get; set; } = 20;
        public int TotalPages => (int)Math.Ceiling((double)TotalResults / PageSize);
    }

    /// View model for user search results
    public class UserSearchResultViewModel
    {
        public string Id { get; set; } = string.Empty;
        public string UserName { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string FullName { get; set; } = string.Empty;
        public bool IsEnabled { get; set; }
        public bool EmailConfirmed { get; set; }
        public bool IsLockedOut { get; set; }
        public int AccessFailedCount { get; set; }
        public DateTime? LastLoginDate { get; set; }
        public DateTime CreatedDate { get; set; }
        public List<string> Roles { get; set; } = new List<string>();
        
        public string AccountStatus => IsLockedOut ? "Locked" : IsEnabled ? "Active" : "Disabled";
        public string AccountStatusBadgeClass => IsLockedOut ? "bg-danger" : IsEnabled ? "bg-success" : "bg-secondary";
    }

    /// Enum for user account status filtering
    public enum UserAccountStatus
    {
        All = 0,
        Active = 1,
        Disabled = 2,
        Locked = 3,
        Unverified = 4
    }

    /// View model for role selection
    public class RoleSelectionViewModel
    {
        public string RoleId { get; set; } = string.Empty;
        public string RoleName { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public bool IsSelected { get; set; }
        public bool IsSystemRole { get; set; }
        public int UserCount { get; set; }
    }
}