using System.ComponentModel.DataAnnotations;

namespace AuthenticationApp.Configuration
{
    // Configuration class for Azure Active Directory settings with validation
    public class AzureAdConfiguration
    {
        [Required(ErrorMessage = "Azure AD Instance is required")]
        [Url(ErrorMessage = "Instance must be a valid URL")]
        public string Instance { get; set; } = "https://login.microsoftonline.com/";

        [Required(ErrorMessage = "Domain is required")]
        public string Domain { get; set; } = string.Empty;

        [Required(ErrorMessage = "TenantId is required")]
        [RegularExpression(@"^[{]?[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}[}]?$",
            ErrorMessage = "TenantId must be a valid GUID")]
        public string TenantId { get; set; } = string.Empty;

        [Required(ErrorMessage = "ClientId is required")]
        [RegularExpression(@"^[{]?[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}[}]?$",
            ErrorMessage = "ClientId must be a valid GUID")]
        public string ClientId { get; set; } = string.Empty;

        // Client secret for confidential client applications
        public string ClientSecret { get; set; } = string.Empty;

        [Required(ErrorMessage = "CallbackPath is required")]
        public string CallbackPath { get; set; } = "/signin-oidc";

        public string[] Scopes { get; set; } = { "User.Read" };

        // Validates the Azure AD configuration
        /// <exception cref="InvalidOperationException">Thrown when configuration is invalid</exception>
        public void Validate()
        {
            var validationResults = new List<ValidationResult>();
            var validationContext = new ValidationContext(this);

            if (!Validator.TryValidateObject(this, validationContext, validationResults, true))
            {
                var errors = string.Join(", ", validationResults.Select(vr => vr.ErrorMessage));
                throw new InvalidOperationException($"Azure AD configuration is invalid: {errors}");
            }

            ValidateInstanceUrl();
            ValidateDomainFormat();
            ValidateCallbackPath();
        }

        // Validates that the Instance URL is a Microsoft login endpoint
        private void ValidateInstanceUrl()
        {
            if (!Instance.Contains("login.microsoftonline.com", StringComparison.OrdinalIgnoreCase) &&
                !Instance.Contains("login.chinacloudapi.cn", StringComparison.OrdinalIgnoreCase) &&
                !Instance.Contains("login.microsoftonline.us", StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException(
                    "Instance URL must be a valid Microsoft login endpoint");
            }
        }


        // Validates the domain format
        private void ValidateDomainFormat()
        {
            if (!string.IsNullOrEmpty(Domain) && !Domain.Contains("."))
            {
                throw new InvalidOperationException(
                    "Domain must be a valid domain name (e.g., contoso.onmicrosoft.com)");
            }
        }

        // Validates the callback path format
        private void ValidateCallbackPath()
        {
            if (!CallbackPath.StartsWith("/"))
            {
                throw new InvalidOperationException(
                    "CallbackPath must start with a forward slash (/)");
            }
        }

        public bool IsProductionReady()
        {
            return !string.IsNullOrEmpty(ClientSecret) &&
                   !TenantId.Equals("common", StringComparison.OrdinalIgnoreCase) &&
                   !Domain.Contains("localhost", StringComparison.OrdinalIgnoreCase);
        }

        // Gets configuration warnings for development environments
        public List<string> GetConfigurationWarnings()
        {
            var warnings = new List<string>();

            if (string.IsNullOrEmpty(ClientSecret))
            {
                warnings.Add("Client secret is not configured - required for production");
            }

            if (TenantId.Equals("common", StringComparison.OrdinalIgnoreCase))
            {
                warnings.Add("Using 'common' tenant - consider using specific tenant ID for production");
            }

            if (Domain.Contains("localhost", StringComparison.OrdinalIgnoreCase))
            {
                warnings.Add("Domain contains localhost - update for production deployment");
            }

            if (Scopes.Length == 1 && Scopes[0] == "User.Read")
            {
                warnings.Add("Only basic User.Read scope configured - consider additional scopes for full functionality");
            }

            return warnings;
        }

        // Returns a string representation of the configuration
        public override string ToString()
        {
            return $"AzureAd Config - Domain: {Domain}, " +
                   $"TenantId: {TenantId?[..8]}..., " +
                   $"ClientId: {ClientId?[..8]}..., " +
                   $"CallbackPath: {CallbackPath}";
        }
    }
}