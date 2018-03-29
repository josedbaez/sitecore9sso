namespace Sitecore9SSO.Pipelines.IdentityProviders
{
    using System;
    using System.Collections.Generic;
    using System.IdentityModel.Tokens;
    using System.Security.Claims;
    using System.Threading.Tasks;
    using IdentityModel.Client;
    using Microsoft.IdentityModel.Protocols.OpenIdConnect;
    using Microsoft.Owin.Security.Notifications;
    using Microsoft.Owin.Security.OpenIdConnect;
    using Owin;
    using Sitecore.Diagnostics;
    using Sitecore.Owin.Authentication.Configuration;
    using Sitecore.Owin.Authentication.Extensions;
    using Sitecore.Owin.Authentication.Pipelines.IdentityProviders;
    using Sitecore.Owin.Authentication.Services;

    public class OktaIdentityProvider : IdentityProvidersProcessor
    {
        protected override string IdentityProviderName => "Okta";
        private const string ClientId = "your clientid here";
        private const string ClientSecret = "your ClientSecret here";
        private const string Authority = "your okta site URL here";
        private const string OauthTokenEndpoint = "/oauth2/v1/token";
        private const string OauthUserInfoEndpoint = "/oauth2/v1/userinfo";
        private const string OAuthRedirectUri = "http://sc9xp0.sc/identity/externallogincallback";
        private const string OpenIdScope = OpenIdConnectScope.OpenIdProfile + " email";

        protected IdentityProvider IdentityProvider { get; set; }

        public OktaIdentityProvider(FederatedAuthenticationConfiguration federatedAuthenticationConfiguration)
            : base(federatedAuthenticationConfiguration)
        {
        }

        protected override void ProcessCore(IdentityProvidersArgs args)
        {
            Assert.ArgumentNotNull(args, "args");
            IdentityProvider = this.GetIdentityProvider();

            var options = new OpenIdConnectAuthenticationOptions
            {
                ClientId = ClientId,
                ClientSecret = ClientSecret,
                Authority = Authority,
                RedirectUri = OAuthRedirectUri,
                ResponseType = OpenIdConnectResponseType.CodeIdToken,
                Scope = OpenIdScope,
                AuthenticationType = IdentityProvider.Name,
                TokenValidationParameters = new TokenValidationParameters
                {
                    NameClaimType = "name"
                },

                Notifications = new OpenIdConnectAuthenticationNotifications
                {
                    AuthorizationCodeReceived = ProcessAuthorizationCodeReceived,
                    RedirectToIdentityProvider = n =>
                    {
                        // If signing out, add the id_token_hint
                        if (n.ProtocolMessage.RequestType == Microsoft.IdentityModel.Protocols.OpenIdConnectRequestType.LogoutRequest )
                        {
                            var idTokenClaim = n.OwinContext.Authentication.User.FindFirst("id_token");

                            if (idTokenClaim != null)
                                n.ProtocolMessage.IdTokenHint = idTokenClaim.Value;
                        }

                        return Task.CompletedTask;
                    }
                }
            };

            args.App.UseOpenIdConnectAuthentication(options);
        }

        private async Task ProcessAuthorizationCodeReceived(AuthorizationCodeReceivedNotification notification)
        {
            // Exchange code for access and ID tokens
            var tokenClient = new TokenClient(Authority + OauthTokenEndpoint, ClientId, ClientSecret);
            var tokenResponse = await tokenClient.RequestAuthorizationCodeAsync(notification.Code, notification.RedirectUri);
            if (tokenResponse.IsError)
                throw new Exception(tokenResponse.Error);

            var userInfoClient = new UserInfoClient(Authority + OauthUserInfoEndpoint);
            var userInfoResponse = await userInfoClient.GetAsync(tokenResponse.AccessToken);
            var claims = new List<Claim>();
            claims.AddRange(userInfoResponse.Claims);
            claims.Add(new Claim("id_token", tokenResponse.IdentityToken));
            claims.Add(new Claim("access_token", tokenResponse.AccessToken));

            if (!string.IsNullOrEmpty(tokenResponse.RefreshToken))
                claims.Add(new Claim("refresh_token", tokenResponse.RefreshToken));

            notification.AuthenticationTicket.Identity.AddClaims(claims);
            notification.AuthenticationTicket.Identity.ApplyClaimsTransformations(new TransformationContext(this.FederatedAuthenticationConfiguration, IdentityProvider));
        }
    }
}
