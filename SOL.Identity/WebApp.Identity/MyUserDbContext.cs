using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace WebApp.Identity {
    public class MyUserDbContext : IdentityDbContext<MyUser> {

        public MyUserDbContext(DbContextOptions<MyUserDbContext> options) : base(options) {

        }

        protected override void OnModelCreating(ModelBuilder builder) {
            base.OnModelCreating(builder);
            
            //Aqui adiciona A PrimaryKey da tabela organização com a tabela MyUser de erda de IdentityUser 
            builder.Entity<Organization>(organization => {
                organization.ToTable("Organizations");
                organization.HasKey(X => X.Id);

                organization.HasMany<MyUser>()
                .WithOne()
                .HasForeignKey(x => x.OrganizationId)
                .IsRequired(false); //Aqui  diz que não é obrigatorio a forekey
            });
        }

    }
}
