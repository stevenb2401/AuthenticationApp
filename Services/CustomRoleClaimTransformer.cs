using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;

public class CustomRoleClaimsTransformer : IClaimsTransformation
{
    public Task<ClaimsPrincipal> TransformAsync(ClaimsPrincipal principal)
    {
        if (principal.Identity is ClaimsIdentity identity && principal.Identity.IsAuthenticated)
        {
            if (!identity.HasClaim(c => c.Type == ClaimTypes.Role))
            {
                var emailClaim = identity.FindFirst(ClaimTypes.Email);

                // Assign "Admin" role if the user's email matches
                if (emailClaim != null && emailClaim.Value.Equals("stevenbyrne243@gmail.com", System.StringComparison.OrdinalIgnoreCase))
                {
                    identity.AddClaim(new Claim(ClaimTypes.Role, "Admin"));
                }

                // Assign additional roles based on email domain (Optional)
                if (emailClaim != null && emailClaim.Value.EndsWith("@example.com", System.StringComparison.OrdinalIgnoreCase))
                {
                    identity.AddClaim(new Claim(ClaimTypes.Role, "User"));
                }
            }
        }
        return Task.FromResult(principal);
    }
}
