using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace WebAPI.Identity.Dto {
    public class UserLoginDto {
        public string Email { get; set; }
        public string Password { get; set; }
    }
}
