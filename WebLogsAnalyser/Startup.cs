using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(WebLogsAnalyser.Startup))]
namespace WebLogsAnalyser
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
