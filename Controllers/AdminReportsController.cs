using Authentication_App.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace Authentication_App.Controllers
{
    public class AdminReportsController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;

        public AdminReportsController(UserManager<IdentityUser> userManager)
        {
            _userManager = userManager ?? throw new ArgumentNullException(nameof(userManager));
        }
    }
}
