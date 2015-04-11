using System.Web.Mvc;

namespace ScottBrady91.IdentityServer3.Example.Client.FormPost
{
    public class FilterConfig
    {
        public static void RegisterGlobalFilters(GlobalFilterCollection filters)
        {
            filters.Add(new HandleErrorAttribute());
        }
    }
}