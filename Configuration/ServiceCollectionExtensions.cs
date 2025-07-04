using AuthenticationApp.Configuration;
using Microsoft.Extensions.Options;

namespace AuthenticationApp.Configuration
{
    /// Extension methods for configuring Azure AD with validation
    public static class ServiceCollectionExtensions
    {
        public static IServiceCollection AddAzureAdConfiguration(
            this IServiceCollection services, 
            IConfiguration configuration)
        {
            // Bind configuration
            var azureAdConfig = new AzureAdConfiguration();
            configuration.GetSection("AzureAd").Bind(azureAdConfig);

            // Validate configuration at startup
            try
            {
                azureAdConfig.Validate();
            }
            catch (InvalidOperationException ex)
            {
                throw new InvalidOperationException(
                    $"Azure AD configuration validation failed: {ex.Message}", ex);
            }

            // Log configuration warnings in development
            var environment = services.BuildServiceProvider()
                .GetService<IWebHostEnvironment>();
            
            if (environment?.IsDevelopment() == true)
            {
                var warnings = azureAdConfig.GetConfigurationWarnings();
                if (warnings.Any())
                {
                    var logger = services.BuildServiceProvider()
                        .GetService<ILogger<AzureAdConfiguration>>();
                    
                    foreach (var warning in warnings)
                    {
                        logger?.LogWarning("Azure AD Configuration Warning: {Warning}", warning);
                    }
                }
            }

            // Register configuration for dependency injection
            services.Configure<AzureAdConfiguration>(
                configuration.GetSection("AzureAd"));

            // Register validation service
            services.AddSingleton<IValidateOptions<AzureAdConfiguration>, 
                AzureAdConfigurationValidator>();

            return services;
        }
    }

    /// Validator for Azure AD configuration options
    public class AzureAdConfigurationValidator : IValidateOptions<AzureAdConfiguration>
    {
        public ValidateOptionsResult Validate(string? name, AzureAdConfiguration options)
        {
            try
            {
                options.Validate();
                return ValidateOptionsResult.Success;
            }
            catch (InvalidOperationException ex)
            {
                return ValidateOptionsResult.Fail(ex.Message);
            }
        }
    }
}