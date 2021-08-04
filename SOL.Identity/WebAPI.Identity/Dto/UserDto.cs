using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

using System.ComponentModel.DataAnnotations;

namespace WebAPI.Identity.Dto {
    public class UserDto {
        public string UserName { get; set; }
        public string UserNameFull { get; set; } 
        
        [EmailAddress]
        public string Email { get; set; }

        [DataType(DataType.Password)]
        public string Password { get; set; }

        [Compare("Password")]
        [DataType(DataType.Password)]
        public string ConfirmePassword { get; set; }
      
    }
}
