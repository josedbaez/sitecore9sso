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
        private const string AppId = "client id here";
        private const string AppSecret = "client secret here";


        public FacebookIdentityProvider(FederatedAuthenticationConfiguration federatedAuthenticationConfiguration)
            : base(federatedAuthenticationConfiguration)
        {
        }

        protected override void ProcessCore(IdentityProvidersArgs args)
        {
            Assert.ArgumentNotNull(args, "args");
            IdentityProvider identityProvider = this.GetIdentityProvider();

            var provider = new Microsoft.Owin.Security.Facebook.FacebookAuthenticationProvider
            {
                OnAuthenticated = (context) =>
                {
                    //map claims
                    context.Identity.ApplyClaimsTransformations(new TransformationContext(this.FederatedAuthenticationConfiguration, identityProvider));
                    return Task.CompletedTask;
                },

                OnReturnEndpoint = (context) =>
                {
                    return Task.CompletedTask;
                }
            };

            var fbAuthOptions = new Microsoft.Owin.Security.Facebook.FacebookAuthenticationOptions
            {
                AppId = AppId,
                AppSecret = AppSecret,
                Provider = provider
            };

            args.App.UseFacebookAuthentication(fbAuthOptions);
        }
    }
}
