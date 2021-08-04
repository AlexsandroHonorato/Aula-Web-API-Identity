using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

using System.Reflection;

using WebAPi.Repository.Context;
using WebAPI.Domain.Entities;
using Microsoft.CodeAnalysis.Options;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using AutoMapper;
using WebAPI.Identity.Helper;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.Authorization;
using WebAPI.Identity.Dto;

namespace WebAPI.Identity {
    public class Startup {
        public Startup(IConfiguration configuration) {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services) {

           //var connectionString = Configuration.GetConnectionString("DefaultConnection"); ;
            var migrationAssembly = typeof(Startup).GetTypeInfo().Assembly.GetName().Name;
            services.AddControllers();

            services.AddDbContext<Context>(
                option => option.UseSqlServer(Configuration.GetConnectionString("DefaultConnection"), 
                sql => sql.MigrationsAssembly(migrationAssembly))                
            );

            services.AddIdentityCore<User>(options => {
                options.SignIn.RequireConfirmedEmail = true;

                options.Password.RequireDigit = false;
                options.Password.RequireNonAlphanumeric = false;
                options.Password.RequireUppercase = false;
                options.Password.RequireLowercase = false;
                options.Password.RequiredLength = 4;

                options.Lockout.MaxFailedAccessAttempts = 3;
                options.Lockout.AllowedForNewUsers = true;

                }).AddRoles<Role>()
                  .AddEntityFrameworkStores<Context>()
                  .AddRoleValidator<RoleValidator<Role>>()
                  .AddRoleManager<RoleManager<Role>>()
                  .AddSignInManager<SignInManager<User>>()
                  .AddDefaultTokenProviders()
                  .AddPasswordValidator<DoesNotContainPasswordValidatorDto<User>>();

            services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer(options => 
                options.TokenValidationParameters = new TokenValidationParameters { 
                
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(Configuration.GetSection("AppSettins:Token").Value)),
                    ValidateIssuer = false,
                    ValidateAudience = false
                }
            );

            //Aqui infroma quanto tempo esse token expira
            services.Configure<DataProtectionTokenProviderOptions>(options =>
                options.TokenLifespan = TimeSpan.FromHours(3)
            );

            //Aqui cria a politica que toda vez que a controle for intanciada ele solicita a autoziração do toke
            services.AddMvc(options => {
                var policy = new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build();
                options.Filters.Add(new AuthorizeFilter(policy));
            }).SetCompatibilityVersion(CompatibilityVersion.Version_3_0);

            var mappingConfig = new MapperConfiguration(mc => mc.AddProfile(new AutoMapperProfile()));

            IMapper mapper = mappingConfig.CreateMapper();
            services.AddSingleton(mapper);

            services.AddCors();

        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env) {
            if (env.IsDevelopment()) {
                app.UseDeveloperExceptionPage();
            }
                        
            app.UseRouting();
            app.UseCors(x => x.AllowAnyOrigin().AllowAnyMethod().AllowAnyHeader());
            app.UseAuthorization();
            //é necessario para funcionar as altenticação
            app.UseAuthentication();

            app.UseEndpoints(endpoints => {
                endpoints.MapControllers();
            });
        }
    }
}
