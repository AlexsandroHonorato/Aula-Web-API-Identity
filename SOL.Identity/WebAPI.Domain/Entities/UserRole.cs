using System;
using System.Collections.Generic;
using System.Text;

using Microsoft.AspNetCore.Identity;

namespace WebAPI.Domain.Entities {
    public class UserRole : IdentityUserRole<int>{     
        public User User { get; set; }
        public Role Role { get; set; }
    }
}
