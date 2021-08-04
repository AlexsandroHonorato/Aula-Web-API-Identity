using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace WebAPI.Identity.Dto {
    public class DoesNotContainPasswordValidatorDto<TUser> : IPasswordValidator<TUser> where TUser : class {
        public async Task<IdentityResult> ValidateAsync(UserManager<TUser> manager, TUser user, string password) {
            var userEmail = await manager.GetEmailAsync(user);

            if (userEmail == password)
                return IdentityResult.Failed(new IdentityError { Description = "A senha não pode igual ao E-mail"});          

            if (password.ToUpper().Contains("PASSWORD"))
                return IdentityResult.Failed(new IdentityError { Description = "A senha não pode ser Password" });

            if (!userEmail.Contains("@"))
                return IdentityResult.Failed(new IdentityError { Description = "O e-mail não é valido" });
            else if (!userEmail.ToUpper().Contains(".COM"))
                return IdentityResult.Failed(new IdentityError { Description = "O e-mail não é valido"});

            return IdentityResult.Success;
        }
    }
}
