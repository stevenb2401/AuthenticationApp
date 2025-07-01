using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Linq;

namespace Authentication_App.Controllers
{
    public class ReportsController : Controller
    {
        // Report page accessible to all users
        public IActionResult Index()
        {
            ViewData["Title"] = "Reports";
            return View();
        }

        // Restricted page for Admins only
        [Authorize(Roles = "Admin")]
        public IActionResult AdminReports()
        {
            ViewData["Title"] = "Admin Reports";

            // Ensures the user is an Admin
            if (!User.IsInRole("Admin"))
            {
                return RedirectToAction("AccessDenied", "Account");
            }

            return View();
        }
    }
}
