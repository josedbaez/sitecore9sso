namespace Sitecore9SSO.Controllers
{
    using System.Web.Mvc;
    using Sitecore.Pipelines.GetSignInUrlInfo;
    using Sitecore.Abstractions;

    public class LoginLinksController : Controller
    {
        public ActionResult Index()
        {
            //get url to redirect to
            var url = "/";
            if(!string.IsNullOrEmpty(Request.QueryString?["item"]))
                url = Request.QueryString["item"];

            var corePipelineManager = DependencyResolver.Current.GetService<BaseCorePipelineManager>();
            var args = new GetSignInUrlInfoArgs("website", url);
            GetSignInUrlInfoPipeline.Run(corePipelineManager, args);

            return View("/Views/LoginLinks.cshtml", args.Result);
        }
    }
}