using System.ComponentModel.DataAnnotations;

namespace Authentication_App.Models
{
    public class CreateUserViewModel
    {
        [Required(ErrorMessage = "Email is required.")]
        [EmailAddress(ErrorMessage = "Invalid email address.")]
        public string Email { get; set; } = string.Empty; // Default value

        [Required(ErrorMessage = "Password is required.")]
        [StringLength(100, ErrorMessage = "The password must be at least {2} characters long.", MinimumLength = 6)]
        [DataType(DataType.Password)]
        public string Password { get; set; } = string.Empty; // Default value

        [Required(ErrorMessage = "Role is required.")]
        public string Role { get; set; } = "User"; // Default value
    }
}
