using System.ComponentModel.DataAnnotations;

namespace Authentication_App.Models
{
    public class LoginViewModel
    {
        [Required(ErrorMessage = "Email or Username is required.")]
        [Display(Name = "Email or Username")]
        public string Email { get; set; } = string.Empty;

        [Required(ErrorMessage = "Password is required.")]
        [DataType(DataType.Password)]
        public string Password { get; set; } = string.Empty;

        [Display(Name = "Remember me?")]
        public bool RememberMe { get; set; }
    }
}