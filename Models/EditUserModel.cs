using System.ComponentModel.DataAnnotations;

namespace Authentication_App.Models
{
    public class EditUserViewModel
    {
        [Required(ErrorMessage = "Email is required.")]
        [EmailAddress(ErrorMessage = "Invalid email address.")]
        public string Email { get; set; } = string.Empty; // Default to an empty string

        [Required(ErrorMessage = "Role is required.")]
        public string Role { get; set; } = string.Empty; // Default to an empty string
    }

}
