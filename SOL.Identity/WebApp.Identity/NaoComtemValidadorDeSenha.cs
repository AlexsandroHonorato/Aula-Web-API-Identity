using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Identity;

namespace WebApp.Identity {
    public class NaoComtemValidadorDeSenha<TUser> : IPasswordValidator<TUser> where TUser : class{
        public async Task<IdentityResult> ValidateAsync(UserManager<TUser> manager, TUser user, string password) {
            var userName = await manager.GetUserNameAsync(user);

            if (userName == password)
                return IdentityResult.Failed(new IdentityError { Description = "A senha não pode ser igual ao E-mail" });

            if (password.Contains("password"))
                return IdentityResult.Failed(new IdentityError { Description = "A senha não pode ser Password" }); // Valida o tipo de senha que não pode ser cadastrada

            return IdentityResult.Success;
        }
    }
}
