using System.Security.Claims;
using System.Web;
using System.Web.Mvc;

namespace ScottBrady91.IdentityServer3.Example.Client.OWIN.Controllers
{
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            return this.View();
        }

        [Authorize]
        public ActionResult Claims()
        {
            return this.View((this.User as ClaimsPrincipal).Claims);
        }

        public ActionResult Signout()
        {
            this.Request.GetOwinContext().Authentication.SignOut();
            return this.Redirect("/Home/Claims");
        }
    }
}