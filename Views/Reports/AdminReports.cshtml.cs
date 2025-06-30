using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Authentication_App.Views.Reports
{
    [Authorize(Roles = "Admin")] // Ensures only Admin users can access this page
    public class AdminReportsModel : PageModel
    {
        public string Message { get; private set; } = string.Empty;

        public void OnGet()
        {
            Message = "Welcome to the Admin Reports page!";
        }
    }
}
