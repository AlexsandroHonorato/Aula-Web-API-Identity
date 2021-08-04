using System;
using System.Collections.Generic;
using System.Text;

using Microsoft.AspNetCore.Identity;

namespace WebAPI.Domain.Entities {
    public class User : IdentityUser<int>{

        public string UserNameFull { get; set; }
        public string Member { get; set; } = "Member";
        public string OrganizationId { get; set; }

        public List<UserRole> UserRoles { get; set; }
    }
}
