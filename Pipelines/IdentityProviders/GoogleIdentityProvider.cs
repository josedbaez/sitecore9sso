namespace Sitecore9SSO.Pipelines.IdentityProviders
{
    using System.Threading.Tasks;
    using Owin;
    using Sitecore.Diagnostics;
    using Sitecore.Owin.Authentication.Configuration;
    using Sitecore.Owin.Authentication.Extensions;
    using Sitecore.Owin.Authentication.Pipelines.IdentityProviders;
    using Sitecore.Owin.Authentication.Services;

    public class GoogleIdentityProvider : IdentityProvidersProcessor
    {
        protected override string IdentityProviderName => "Google";
        private const string ClientId = "your clientid here";
        private const string ClientSecret = "your clientsecret here";

        protected IdentityProvider IdentityProvider { get; set; }

        public GoogleIdentityProvider(FederatedAuthenticationConfiguration federatedAuthenticationConfiguration)
            : base(federatedAuthenticationConfiguration)
        {
        }

        protected override void ProcessCore(IdentityProvidersArgs args)
        {
            Assert.ArgumentNotNull(args, "args");
            IdentityProvider = this.GetIdentityProvider();

            var provider = new Microsoft.Owin.Security.Google.GoogleOAuth2AuthenticationProvider
            {
                OnAuthenticated = (context) =>
                {
                    //map claims
                    context.Identity.ApplyClaimsTransformations(new TransformationContext(this.FederatedAuthenticationConfiguration, IdentityProvider));
                    return Task.CompletedTask;
                }
            };

            var googleAuthOptions = new Microsoft.Owin.Security.Google.GoogleOAuth2AuthenticationOptions
            {
                ClientId = ClientId,
                ClientSecret = ClientSecret,
                Provider = provider,
                AuthenticationType = IdentityProvider.Name
            };

            args.App.UseGoogleAuthentication(googleAuthOptions);
        }
    }
}
