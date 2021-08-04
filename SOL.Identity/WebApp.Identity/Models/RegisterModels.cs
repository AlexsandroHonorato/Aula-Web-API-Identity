using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

using System.ComponentModel.DataAnnotations;

namespace WebApp.Identity.Models {
    public class RegisterModels {   
        public string UserName { get; set; }

        [DataType(DataType.Password)]
        public string Password { get; set; }
        
        [Compare("Password")]
        [DataType(DataType.Password)]
        public string ConfirmPassword { get; set; }
    }
}
