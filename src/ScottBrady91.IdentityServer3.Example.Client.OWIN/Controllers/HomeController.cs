using System.Web.Mvc;

namespace ScottBrady91.IdentityServer3.Example.Client.OWIN.Controllers
{
    public sealed class HomeController : Controller
    {
        public ActionResult Index()
        {
            return this.View();
        }
    }
}