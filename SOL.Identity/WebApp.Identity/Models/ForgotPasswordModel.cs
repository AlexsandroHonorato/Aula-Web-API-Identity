using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

using System.ComponentModel.DataAnnotations;

namespace WebApp.Identity.Models {
    public class ForgotPasswordModel {

        [Required]
        [EmailAddress]
        public string Email { get; set; }
    }
}
