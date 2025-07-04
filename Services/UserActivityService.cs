using Microsoft.ApplicationInsights;
using Microsoft.ApplicationInsights.DataContracts;
using Microsoft.ApplicationInsights.Extensibility;
using Microsoft.ApplicationInsights.Channel;
using System.Security.Claims;

namespace AuthenticationApp.Services
{
    // Custom Telemetry Initialiser
    public class UserTelemetryInitializer : ITelemetryInitializer
    {
        private readonly IHttpContextAccessor _httpContextAccessor;

        public UserTelemetryInitializer(IHttpContextAccessor httpContextAccessor)
        {
            _httpContextAccessor = httpContextAccessor;
        }

        public void Initialize(ITelemetry telemetry)
        {
            var httpContext = _httpContextAccessor.HttpContext;
            if (httpContext?.User?.Identity?.IsAuthenticated == true)
            {
                var userId = httpContext.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
                var userEmail = httpContext.User.FindFirst(ClaimTypes.Email)?.Value;
                var authMethod = httpContext.User.FindFirst("authmethod")?.Value ?? "Unknown";

                if (!string.IsNullOrEmpty(userId))
                {
                    telemetry.Context.User.Id = userId;
                    telemetry.Context.User.AuthenticatedUserId = userEmail ?? userId;
                    
                    // Adds custom properties
                    if (telemetry is ISupportProperties telemetryWithProperties)
                    {
                        telemetryWithProperties.Properties["AuthenticationMethod"] = authMethod;
                        telemetryWithProperties.Properties["UserEmail"] = userEmail ?? "Unknown";
                        
                        // Tracks user roles
                        var roles = httpContext.User.FindAll(ClaimTypes.Role)
                            .Union(httpContext.User.FindAll("roles"))
                            .Select(c => c.Value)
                            .ToList();
                        
                        if (roles.Any())
                        {
                            telemetryWithProperties.Properties["UserRoles"] = string.Join(", ", roles);
                        }
                    }
                }
            }
        }
    }

    // User Activity Tracking Service
    public interface IUserActivityService
    {
        void TrackUserLogin(string? userId, string email, string authMethod, bool isSuccessful);
        void TrackUserLogout(string? userId, string email);
        void TrackUserAction(string? userId, string action, Dictionary<string, string>? properties = null);
        void TrackRoleAssignment(string? adminUserId, string targetUserId, string role, string action);
    }

    public class UserActivityService : IUserActivityService
    {
        private readonly TelemetryClient _telemetryClient;
        private readonly ILogger<UserActivityService> _logger;

        public UserActivityService(TelemetryClient telemetryClient, ILogger<UserActivityService> logger)
        {
            _telemetryClient = telemetryClient;
            _logger = logger;
        }

        public void TrackUserLogin(string? userId, string email, string authMethod, bool isSuccessful)
        {
            if (string.IsNullOrEmpty(userId)) return;
            
            var eventTelemetry = new EventTelemetry("UserLogin");
            eventTelemetry.Properties["UserId"] = userId;
            eventTelemetry.Properties["Email"] = email;
            eventTelemetry.Properties["AuthMethod"] = authMethod;
            eventTelemetry.Properties["IsSuccessful"] = isSuccessful.ToString();
            eventTelemetry.Properties["Timestamp"] = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ");

            _telemetryClient.TrackEvent(eventTelemetry);
            
            _logger.LogInformation("User login tracked: {UserId} via {AuthMethod}, Success: {IsSuccessful}", 
                userId, authMethod, isSuccessful);
        }

        public void TrackUserLogout(string? userId, string email)
        {
            if (string.IsNullOrEmpty(userId)) return;
            
            var eventTelemetry = new EventTelemetry("UserLogout");
            eventTelemetry.Properties["UserId"] = userId;
            eventTelemetry.Properties["Email"] = email;
            eventTelemetry.Properties["Timestamp"] = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ");

            _telemetryClient.TrackEvent(eventTelemetry);
        }

        public void TrackUserAction(string? userId, string action, Dictionary<string, string>? properties = null)
        {
            if (string.IsNullOrEmpty(userId)) return;
            
            var eventTelemetry = new EventTelemetry($"UserAction_{action}");
            eventTelemetry.Properties["UserId"] = userId;
            eventTelemetry.Properties["Action"] = action;
            eventTelemetry.Properties["Timestamp"] = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ");

            if (properties != null)
            {
                foreach (var prop in properties)
                {
                    eventTelemetry.Properties[prop.Key] = prop.Value;
                }
            }

            _telemetryClient.TrackEvent(eventTelemetry);
        }

        public void TrackRoleAssignment(string? adminUserId, string targetUserId, string role, string action)
        {
            if (string.IsNullOrEmpty(adminUserId) || string.IsNullOrEmpty(targetUserId)) return;
            
            var eventTelemetry = new EventTelemetry("RoleAssignment");
            eventTelemetry.Properties["AdminUserId"] = adminUserId;
            eventTelemetry.Properties["TargetUserId"] = targetUserId;
            eventTelemetry.Properties["Role"] = role;
            eventTelemetry.Properties["Action"] = action;
            eventTelemetry.Properties["Timestamp"] = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ");

            _telemetryClient.TrackEvent(eventTelemetry);
            
            _logger.LogInformation("Role {Action}: {Role} for user {TargetUserId} by admin {AdminUserId}", 
                action, role, targetUserId, adminUserId);
        }
    }
}