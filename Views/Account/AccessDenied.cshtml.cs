using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Authentication_App.Views.Account
{
    public class AccessDeniedModel : PageModel
    {
        public string Message { get; private set; } = string.Empty;
        public string UserName { get; private set; } = string.Empty;

        public void OnGet()
        {
            UserName = User.Identity?.Name ?? "Guest";
            Message = $"Sorry, {UserName}. You don’t have permission to view this page.";
        }

    }
}
