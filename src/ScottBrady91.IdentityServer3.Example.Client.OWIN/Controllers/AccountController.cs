using System.Web;
using System.Web.Mvc;

namespace ScottBrady91.IdentityServer3.Example.Client.OWIN.Controllers
{
    public sealed class AccountController : Controller
    {
        [Authorize]
        public ActionResult SignIn()
        {
            return this.Redirect("/");
        }

        public ActionResult SignOut()
        {
            this.Request.GetOwinContext().Authentication.SignOut();
            return this.Redirect("/");
        }
    }
}