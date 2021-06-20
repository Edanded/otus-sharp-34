using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;

namespace WebApplicationAuth
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }
        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        // For more information on how to configure your application, visit https://go.microsoft.com/fwlink/?LinkID=398940
        public void ConfigureServices(IServiceCollection services)
        {
            var authOptions = Configuration.GetSection("ApplicationOptions");

            services
      //   .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)

                .AddAuthentication(options =>
                            {

                                options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                            })
                .AddJwtBearer(options =>
                    {
                        options.RequireHttpsMetadata = false;
                        options.TokenValidationParameters = TokenHelper.GetJwtValidationParameters();
                    })
                .AddCookie(options =>
                        {
                            options.LoginPath = "/google-login"; // Must be lowercase
                        })
                .AddGoogle(options =>
                         {
                             var googleAuthNSection =
                                 Configuration.GetSection("OAuth2:Google");

                             options.ClientId = googleAuthNSection["ClientId"];
                             options.ClientSecret = googleAuthNSection["Secret"];


                             options.Events.OnTicketReceived = (context) =>
                                         {
                                             Console.WriteLine(context.HttpContext.User);
                                             return Task.CompletedTask;
                                         };
                             options.Events.OnCreatingTicket = (context) =>
                             {
                                 Console.WriteLine(context.Identity);
                                 return Task.CompletedTask;
                             };
                         });


            services.AddControllersWithViews();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app)
        {
            app.UseDeveloperExceptionPage();

            app.UseDefaultFiles();
            app.UseStaticFiles();

            app.UseRouting();

            app.UseAuthentication();
            app.UseAuthorization();

            app.UseCookiePolicy(new CookiePolicyOptions()
            {
                MinimumSameSitePolicy = SameSiteMode.Lax
            });
            app.UseEndpoints(endpoints =>
            {
                endpoints.MapDefaultControllerRoute();
            });
        }
    }
}
