using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

using WebApp.Identity.Models;
using Microsoft.AspNetCore.Identity;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using System.Reflection.Metadata;
using Microsoft.AspNetCore.Http;
using System.Security.Cryptography.X509Certificates;

namespace WebApp.Identity.Controllers {
    public class HomeController : Controller {
        private readonly ILogger<HomeController> _logger;
        private readonly UserManager<MyUser> _userManager;
        private readonly IUserClaimsPrincipalFactory<MyUser> _userClaimsPrincipalFactory;
        private readonly SignInManager<MyUser> _signInManager;

        public HomeController(ILogger<HomeController> logger,
                              UserManager<MyUser> userManager,
                              IUserClaimsPrincipalFactory<MyUser> userClaimsPrincipalFactory,
                              SignInManager<MyUser> signInManager) {
            _logger = logger;
            _userManager = userManager;
            _userClaimsPrincipalFactory = userClaimsPrincipalFactory;
            _signInManager = signInManager;
        }

        public IActionResult Index() {
            return View();
        }

        public IActionResult Privacy() {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Login(LoginModel model) {

            if (ModelState.IsValid) {

                var user = await _userManager.FindByNameAsync(model.UserName);

                if (user != null && !await _userManager.IsLockedOutAsync(user)) {

                    //var identity = new ClaimsIdentity("Identity.Application");

                    //identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, user.Id));
                    //identity.AddClaim(new Claim(ClaimTypes.Name, user.UserName));

                    if (await _userManager.CheckPasswordAsync(user, model.Password)) {

                        if (!await _userManager.IsEmailConfirmedAsync(user)) {

                            ModelState.AddModelError("", "O E-mail não foi confirmado, por favor verifique na sua caixa de entrada ou na pasta de span. Obrigado!");

                            return View();
                        }

                        await _userManager.ResetAccessFailedCountAsync(user); //Aqui reseta a quantidade de vezes se o usuário acetar antes do valor colocado de erro

                        if (await _userManager.GetTwoFactorEnabledAsync(user)) {
                            var validador = await _userManager.GetValidTwoFactorProvidersAsync(user);

                            if (validador.Contains("Email")) {
                                var token = await _userManager.GenerateTwoFactorTokenAsync(user, "Email");

                                System.IO.File.WriteAllText("email2sv.txt", token);

                                await HttpContext.SignInAsync(IdentityConstants.TwoFactorUserIdScheme, Store2FA(user.Id, "Email"));

                                return RedirectToAction("TwoFactor");
                            }
                        }

                        var principal = await _userClaimsPrincipalFactory.CreateAsync(user);

                        await HttpContext.SignInAsync(IdentityConstants.ApplicationScheme, principal);

                        return RedirectToAction("About");
                    }

                    await _userManager.AccessFailedAsync(user);

                    if (await _userManager.IsLockedOutAsync(user)) {

                        //Criar email informando para o usuário quer tentaro usar o email dele para fazer o Login altere a senha
                    }
                }

                ModelState.AddModelError("", "Usuário ou Senha Invalida");
            }

            return View();
        }


        public ClaimsPrincipal Store2FA(string userId, string provider) {
            var identity = new ClaimsIdentity(new List<Claim> {
                new Claim("sub", userId),
                new Claim("amr", provider)

            }, IdentityConstants.TwoFactorUserIdScheme);

            return new ClaimsPrincipal(identity);
        }


        [HttpGet]
        public async Task<IActionResult> Login() {

            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Register(RegisterModels model) {

            if (ModelState.IsValid) {

                var user = await _userManager.FindByNameAsync(model.UserName);

                if (user == null) {

                    user = new MyUser() {
                        Id = Guid.NewGuid().ToString(),
                        UserName = model.UserName,
                        Email = model.UserName
                    };

                    var result = await _userManager.CreateAsync(user, model.Password);

                    if (result.Succeeded) {

                        var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                        var confirmationEmail = Url.Action("ConfirmEmailAddress", "Home", new { token = token, email = user.Email }, Request.Scheme);

                        System.IO.File.WriteAllText("confirmationEmail.txt", confirmationEmail);

                    } else {
                        foreach (var error in result.Errors) {

                            ModelState.AddModelError("", error.Description);
                        }

                        return View();
                    }

                    return View("Success");
                }
            }

            return View();
        }

        [HttpGet]
        public async Task<IActionResult> Register() {

            return View();
        }

        [HttpGet]
        public async Task<IActionResult> ConfirmEmailAddress(string token, string email) {

            var user = await _userManager.FindByEmailAsync(email);

            if (user != null) {

                var result = await _userManager.ConfirmEmailAsync(user, token);

                if (result.Succeeded) {

                    return View("Success");
                }
            }

            return View("Error");
        }

        [HttpGet]
        public async Task<IActionResult> ForgotPassword() {

            return View();
        }

        [HttpPost]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordModel model) {

            if (ModelState.IsValid) {

                var user = await _userManager.FindByEmailAsync(model.Email);

                if (user != null) {

                    var token = await _userManager.GeneratePasswordResetTokenAsync(user);
                    var resetURL = Url.Action("ResetPassword", "Home", new { token = token, email = model.Email }, Request.Scheme);

                    System.IO.File.WriteAllText("resetLink.txt", resetURL);

                    return View("Success");

                } else {
                    ModelState.AddModelError("", "Email Invalido"); //Ou pode implementar uma pagina com a informação de Email não incontrado
                }

            }

            return View();
        }

        [HttpGet]
        public async Task<IActionResult> ResetPassword(string token, string email) {

            return View(new ResetPasswordModel { Token = token, Email = email });
        }

        [HttpPost]
        public async Task<IActionResult> ResetPassword(ResetPasswordModel model) {

            if (ModelState.IsValid) {

                var user = await _userManager.FindByEmailAsync(model.Email);

                if (user != null) {

                    var result = await _userManager.ResetPasswordAsync(user, model.Token, model.Password);

                    if (!result.Succeeded) {

                        foreach (var error in result.Errors) {

                            ModelState.AddModelError("", error.Description);
                        }

                        return View();
                    }

                    return View("Success");
                }

                ModelState.AddModelError("", "Pedido Invalido");
            }

            return View();
        }

        [HttpGet]
        public async Task<IActionResult> TwoFactor() {

            return View();
        }


        [HttpPost]
        public async Task<IActionResult> TwoFactor(TwoFactorModel model) {
            var result = await HttpContext.AuthenticateAsync(IdentityConstants.TwoFactorUserIdScheme);
            if (!result.Succeeded) {
                ModelState.AddModelError("", "Seu token expirou");

                return View();
            }

            if (ModelState.IsValid) {

                var user = await _userManager.FindByIdAsync(result.Principal.FindFirstValue("sub"));

                if (user != null) {
                    var isValid = await _userManager.VerifyTwoFactorTokenAsync(
                        user, 
                        result.Principal.FindFirstValue("amr"), 
                        model.Token);

                    if (isValid) {
                        await HttpContext.SignOutAsync(IdentityConstants.TwoFactorUserIdScheme);

                        var claimsPrincipal = await _userClaimsPrincipalFactory.CreateAsync(user);
                        await HttpContext.SignInAsync(IdentityConstants.ApplicationScheme, claimsPrincipal);

                        return RedirectToAction("About");
                    }

                    ModelState.AddModelError("", "Token Invalido");
                    return View();
                }

                ModelState.AddModelError("", "Requirimento Invalido");
            }
            return View();
        }

        [HttpGet]
        [Authorize]
        public IActionResult About() {

            return View();
        }

        [HttpGet]
        public IActionResult Success() {

            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error() {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
