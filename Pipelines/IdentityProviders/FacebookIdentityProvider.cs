namespace Sitecore9SSO.Pipelines.IdentityProviders
{
    using System.Threading.Tasks;
    using Owin;
    using Sitecore.Diagnostics;
    using Sitecore.Owin.Authentication.Configuration;
    using Sitecore.Owin.Authentication.Extensions;
    using Sitecore.Owin.Authentication.Pipelines.IdentityProviders;
    using Sitecore.Owin.Authentication.Services;

    public class FacebookIdentityProvider : IdentityProvidersProcessor
    {
        protected override string IdentityProviderName => "Facebook";
        private const string AppId = "your appid here";
        private const string AppSecret = "your appsecret here";

        protected IdentityProvider IdentityProvider { get; set; }

        public FacebookIdentityProvider(FederatedAuthenticationConfiguration federatedAuthenticationConfiguration)
            : base(federatedAuthenticationConfiguration)
        {
        }

        protected override void ProcessCore(IdentityProvidersArgs args)
        {
            Assert.ArgumentNotNull(args, "args");
            IdentityProvider = this.GetIdentityProvider();

            var provider = new Microsoft.Owin.Security.Facebook.FacebookAuthenticationProvider
            {
                OnAuthenticated = (context) =>
                {
                    //map claims
                    context.Identity.ApplyClaimsTransformations(new TransformationContext(this.FederatedAuthenticationConfiguration, IdentityProvider));
                    return Task.CompletedTask;
                },
                OnReturnEndpoint = (context) =>
                {
                    return Task.CompletedTask;
                },
            };

            var fbAuthOptions = new Microsoft.Owin.Security.Facebook.FacebookAuthenticationOptions
            {
                AppId = AppId,
                AppSecret = AppSecret,
                Provider = provider,
                AuthenticationType = IdentityProvider.Name
            };

            args.App.UseFacebookAuthentication(fbAuthOptions);
        }
    }
}
