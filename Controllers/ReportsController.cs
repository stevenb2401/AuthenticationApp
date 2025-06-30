using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Linq;

namespace Authentication_App.Controllers
{
    public class ReportsController : Controller
    {
        // Publicly accessible action for all users
        public IActionResult Index()
        {
            ViewData["Title"] = "Reports"; // Set the title for the view
            return View(); // Returns the default view for general reports
        }

        // Restricted action for Admins only
        [Authorize(Roles = "Admin")]
        public IActionResult AdminReports()
        {
            ViewData["Title"] = "Admin Reports"; // Set the title for the Admin view

            // Debugging: Log current user roles (optional)
            var roles = User.Claims.Where(c => c.Type == System.Security.Claims.ClaimTypes.Role).Select(c => c.Value);
            Console.WriteLine($"User Roles: {string.Join(", ", roles)}");

            // Ensure the user is truly an Admin (double-check)
            if (!User.IsInRole("Admin"))
            {
                return RedirectToAction("AccessDenied", "Account");
            }

            return View(); // Returns the Admin reports view
        }
    }
}
