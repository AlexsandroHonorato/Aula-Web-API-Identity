using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using WebAPI.Domain.Entities;
using AutoMapper;
using WebAPI.Identity.Dto;
using Microsoft.EntityFrameworkCore.Metadata.Internal;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.Authorization;
using System.Reflection.Metadata.Ecma335;

// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace WebAPI.Identity.Controllers {
    [Route("api/[controller]")]
    [ApiController]
    [Authorize(AuthenticationSchemes = "Bearer")]
    public class UserController : ControllerBase {

        private readonly IConfiguration _configuration;
        private readonly UserManager<User> _userManager;
        private readonly SignInManager<User> _signInManager;
        private readonly IMapper _mapper;

        public UserController(IConfiguration configuration, UserManager<User> userManager,
                               SignInManager<User> signInManager, IMapper mapper) {
            _configuration = configuration;
            _userManager = userManager;
            _signInManager = signInManager;
            _mapper = mapper;
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult Get() {
            return Ok(new UserDto());
        }

        //POST api/User
        [HttpPost("Register")]
        [AllowAnonymous]
        public async Task<IActionResult> Register(UserDto userDto) {
            try {

                var user = await _userManager.FindByEmailAsync(userDto.Email);

                if (user == null) {
                    user = new User {
                        UserName = userDto.UserName,
                        UserNameFull = userDto.UserNameFull,
                        Email = userDto.Email
                    };

                    var result = await _userManager.CreateAsync(user, userDto.Password);

                    if (result.Succeeded) {

                        var aapUser = await _userManager.Users.FirstOrDefaultAsync(u => u.NormalizedEmail == user.Email.ToUpper());

                        var token = GenerateJWTToken(aapUser).Result;
                        var tokeConfirmationEmail = await _userManager.GenerateEmailConfirmationTokenAsync(user);

                        var confirmationEmail = Url.Action("ConfirmEmailAddress", "user", new { token = tokeConfirmationEmail, email = user.Email }, Request.Scheme);

                        System.IO.File.WriteAllText("confirmationEmail.txt", confirmationEmail);

                        return Ok(confirmationEmail);

                    }else{
                        foreach (var error in result.Errors) {
                            return this.StatusCode(StatusCodes.Status400BadRequest, $"ERROR - {error.Description}");
                        }
                    }
                }

                return Unauthorized(this.StatusCode(StatusCodes.Status403Forbidden, $"O e-mail já existe"));

            } catch (Exception error) {

                return this.StatusCode(StatusCodes.Status500InternalServerError, $"ERROR - {error.Message}");
            }

        }


        [HttpPost("Login")]
        [AllowAnonymous]
        public async Task<IActionResult> Login(UserLoginDto userLoginDto) {
            try {

                var user = await _userManager.FindByEmailAsync(userLoginDto.Email);

                if (user != null) {
                    var result = await _signInManager.CheckPasswordSignInAsync(user, userLoginDto.Password, false);

                    if (!await _userManager.IsEmailConfirmedAsync(user)) {

                        return this.StatusCode(StatusCodes.Status500InternalServerError, $"ERROR - E-MAIL NOT CONFIRMED");
                    }


                    if (result.Succeeded) {
                        var appUser = await _userManager.Users.FirstOrDefaultAsync(u => u.NormalizedEmail == user.Email.ToUpper());

                        var userToReturn = _mapper.Map<UserDto>(appUser);

                        return Ok(new {
                            token = GenerateJWTToken(appUser).Result,
                            user = userToReturn
                        });
                    }
                }

                return Unauthorized();

            } catch (Exception error) {

                return this.StatusCode(StatusCodes.Status500InternalServerError, $"ERROR {error.Message}");
            }
        }

        [HttpGet("ConfirmEmailAddress")]
        [AllowAnonymous]
        public async Task<IActionResult> ConfirmEmailAddress(string token, string email) {
            try {
                var user = await _userManager.FindByEmailAsync(email);

                if (user != null) {

                    var result = await _userManager.ConfirmEmailAsync(user, token);

                    if (result.Succeeded) {

                        return Ok("Success");
                    }
                }
            } catch (Exception error) {

                return this.StatusCode(StatusCodes.Status500InternalServerError, $"ERROR {error.Message}");
            }

            return Ok();
        }

        [HttpPost("ResendEmailConfirmation")]
        [AllowAnonymous]
        public async Task<IActionResult> ResendEmailConfirmation(UserLoginDto userLoginDto) {
            try {
                var user = await _userManager.FindByEmailAsync(userLoginDto.Email);

                if (user != null) {
                    var tokeConfirmationEmail = await _userManager.GenerateEmailConfirmationTokenAsync(user);

                    var confirmationEmail = Url.Action("ConfirmEmailAddress", "user", new { token = tokeConfirmationEmail, email = user.Email }, Request.Scheme);

                    System.IO.File.WriteAllText("confirmationEmail.txt", confirmationEmail);

                    return Ok(confirmationEmail);

                } else {
                    return this.StatusCode(StatusCodes.Status401Unauthorized, "ERROR - E-MAIL IS NOT VALID");
                }
            } catch (Exception error) {

                return this.StatusCode(StatusCodes.Status500InternalServerError, $"ERROR - {error.Message}");
            }
            return Ok();
        }

        [HttpGet("ForgotPassword")]
        [AllowAnonymous]
        public async Task<IActionResult> ForgotPassword(){

            return Ok();
        }

        [HttpPost("ForgotPassword")]
        [AllowAnonymous]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordDto forgotPassword) {
            try {
                if (ModelState.IsValid) {
                    var user = await _userManager.FindByEmailAsync(forgotPassword.Email);

                    if (user != null) {

                        var token = await _userManager.GeneratePasswordResetTokenAsync(user);
                        var resetURL = Url.Action("resetpassword", "user", new { token = token, email = forgotPassword.Email }, Request.Scheme);

                        System.IO.File.WriteAllText("resetLink.txt", resetURL);

                        return this.StatusCode(StatusCodes.Status200OK, $"Toke: {token}");

                    } else
                        return this.StatusCode(StatusCodes.Status500InternalServerError, $"ERROR - USER IS NOT VALID");
                }

                return Unauthorized(this.StatusCode(StatusCodes.Status500InternalServerError));

            } catch (Exception error) {

                return this.StatusCode(StatusCodes.Status500InternalServerError, $"ERROR {error.Message}");
            }          
        }

        [HttpGet("ResetPassword")]
        [AllowAnonymous]
        public async Task<IActionResult> ResetPassword(string token, string email) {
            try {
                return Ok();
            } catch (Exception error) {

                return this.StatusCode(StatusCodes.Status500InternalServerError, $"ERROR {error.Message}");
            }
            return Ok();
        }

        [HttpPost("ResetPassword")]
        [AllowAnonymous]
        public async Task<IActionResult> ResetPassword(ResetPasswordDto resetPassword) {
            try {
                if (ModelState.IsValid) {
                    var user = await _userManager.FindByEmailAsync(resetPassword.Email);

                    if (user != null) {
                        var result = await _userManager.ResetPasswordAsync(user, resetPassword.Token, resetPassword.Password);

                        if (!result.Succeeded) {
                            foreach (var error in result.Errors) {
                                return this.StatusCode(StatusCodes.Status500InternalServerError, $"ERROR {error.Description}");
                            }
                        }
                        return Ok("Password Reset");                    
                    }

                    return this.StatusCode(StatusCodes.Status500InternalServerError, $"ERROR - INVALID REQUEST");
                }

                return Unauthorized();

            } catch (Exception error){

                return this.StatusCode(StatusCodes.Status500InternalServerError, $"ERROR {error.Message}");

            }

        }

        private async Task<string> GenerateJWTToken(User user) {
            
            //Aqui cria as credenciais (Roles)
            var claims = new List<Claim> {
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim(ClaimTypes.Email, user.Email)
                };

            //Aqui pega as Credenciais (Roles), do usuário
            var roles = await _userManager.GetRolesAsync(user);

            foreach (var role in roles) {

                claims.Add(new Claim(ClaimTypes.Role, role));
            }
            //Aqui cria uma criptografia com base no token do AppSetting
            var key = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(_configuration.GetSection("AppSettins:Token").Value));
            //Aqui cria a Credencial, como base no tipo da chave especificada (a Key + HmacSha512Signature)
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);
            //Aqui gera a descrição do Token
            var tokenDrescription = new SecurityTokenDescriptor {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.Now.AddDays(1),
                SigningCredentials = creds
            };
            //Aqui gera o Token
            var tokenHandler = new JwtSecurityTokenHandler();
            //Aqui cria o Token
            var token = tokenHandler.CreateToken(tokenDrescription);

            return tokenHandler.WriteToken(token);
        }

        // PUT api/<UserController>/5
        [HttpPut("{id}")]
        public void Put(int id, [FromBody] string value) {
        }

        // DELETE api/<UserController>/5
        [HttpDelete("{id}")]
        public void Delete(int id) {
        }
    }
}
