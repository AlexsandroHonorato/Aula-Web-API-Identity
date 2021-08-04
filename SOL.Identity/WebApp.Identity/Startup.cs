using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;

using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.CodeAnalysis.Options;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace WebApp.Identity {
    public class Startup {
        public Startup(IConfiguration configuration) {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services) {
           
            services.AddControllersWithViews();

            var connectionString = @"Integrated Security=SSPI;Persist Security Info=False;Initial Catalog=IdentityCurso;Data Source=DESKTOP-6H183G7\SQLEXPRESS";
            var migrationAssembly = typeof(Startup).GetTypeInfo().Assembly.GetName().Name;

            services.AddDbContext<MyUserDbContext>(option => option.UseSqlServer(connectionString, sql => sql.MigrationsAssembly(migrationAssembly)));
           
            services.AddIdentity<MyUser, IdentityRole>(options => {                
                options.SignIn.RequireConfirmedEmail = true; //Aqui configura o campo EmailConfirm se ele estiver 0 não foi confirmado
                
                options.Password.RequireDigit = false;
                options.Password.RequireNonAlphanumeric = false;
                options.Password.RequireLowercase = false;
                options.Password.RequireUppercase = false;
                options.Password.RequiredLength = 4;

                options.Lockout.MaxFailedAccessAttempts = 3;
                options.Lockout.AllowedForNewUsers = true;

            }).AddEntityFrameworkStores<MyUserDbContext>()
            .AddDefaultTokenProviders()
            .AddPasswordValidator<NaoComtemValidadorDeSenha<MyUser>>(); //Aqui configura minha classe de regra de senha
            
            
            //services.AddScoped<IUserStore<MyUser>, UserOnlyStore<MyUser, MyUserDbContext>>(); //Pimrtira mandeira de se criar o serviço
            //services.AddAuthentication("cookies").AddCookie("cookies", options => options.LoginPath = "/Home/Login");  //Pimrtira mandeira de se criar o serviço

            services.AddScoped<IUserClaimsPrincipalFactory<MyUser>, MyUserClaimsPrincipalFactory>();
            services.Configure<DataProtectionTokenProviderOptions>(options => options.TokenLifespan = TimeSpan.FromHours(3));
            services.ConfigureApplicationCookie(options => options.LoginPath = "/Home/Login");

        }



        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env) {
            if (env.IsDevelopment()) {
                app.UseDeveloperExceptionPage();
            } else {
                app.UseExceptionHandler("/Home/Error");
            }

            app.UseAuthentication();

            app.UseStaticFiles();

            app.UseRouting();

            app.UseAuthorization();

            app.UseEndpoints(endpoints => {
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Login}/{id?}");
            });
        }
    }
}
