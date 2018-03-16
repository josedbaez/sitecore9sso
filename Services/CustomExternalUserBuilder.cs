using Sitecore.Owin.Authentication.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.AspNet.Identity;
using Sitecore.Diagnostics;

namespace Sitecore9SSO.Services
{
    public class CustomExternalUserBuilder : Sitecore.Owin.Authentication.Services.DefaultExternalUserBuilder
    {
        public CustomExternalUserBuilder(bool isPersistentUser)
            : base(isPersistentUser)
        {
        }

        public CustomExternalUserBuilder(string isPersistentUser) 
            : base(bool.Parse(isPersistentUser))
        {
        }

        protected override string CreateUniqueUserName(UserManager<ApplicationUser> userManager, ExternalLoginInfo externalLoginInfo)
        {
            Assert.ArgumentNotNull(userManager, "userManager");
            Assert.ArgumentNotNull(externalLoginInfo, "externalLoginInfo");

            return externalLoginInfo.ExternalIdentity.FindFirstValue("FullName");
        }
    }
}