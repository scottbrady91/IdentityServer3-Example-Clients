using System.Web.Mvc;

namespace ScottBrady91.IdentityServer3.Example.Client.FormPost.Controllers
{
    public sealed class HomeController : Controller
    {
        public ActionResult Index()
        {
            return this.View();
        }
    }
}