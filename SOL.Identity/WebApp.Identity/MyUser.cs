using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Identity;

namespace WebApp.Identity {
    public class MyUser : IdentityUser {

        // As proriedades abaixo não é amis necessária pois já existe na classe IdentyUser
        // onde minha classe MyUser esta Erdando 
        //public string Id { get; set; }
        //public string UserName { get; set; }
        //public string UserEmail { get; set; }
        //public string NormalizedUserName { get; set; }
        //public string PasswordHash { get; set; }

        public string NomeCompleto { get; set; }
        public string Member { get; set; } = "Member";
        public string OrganizationId { get; set; }
    }

    public class Organization {

        public string Id { get; set; }
        public string Name { get; set; }

    }
}
