using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Permissions;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

using WebAPI.Domain.Entities;
using WebAPI.Identity.Dto;

// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace WebAPI.Identity.Controllers {
    [Route("api/[controller]")]
    [ApiController]
    [Authorize(AuthenticationSchemes = "Bearer")]
    public class RoleController : ControllerBase {
        private readonly RoleManager<Role> _roleManager;
        private readonly UserManager<User> _userManager;

        public RoleController(RoleManager<Role> roleManager, UserManager<User> userManager) {
            _roleManager = roleManager;
            _userManager = userManager;
        }

        // GET: api/<RoleController>
        [HttpGet]
        [Authorize(Roles = "Administrador")]
        public IActionResult Get() {
            return Ok(new { 
                role = new RoleDto(),
                updateUserRoleDto = new UpdateUserRoleDto()
            });
        }

        // GET api/<RoleController>/5
        [HttpGet("{id}", Name = "Get")]
        [Authorize(Roles = "Administrador, Gerente")]
        public string Get(int id) {
            return "value";
        }

        [HttpPost("CreateRole")]
        public async Task<IActionResult> CreateRole(RoleDto roleDto) {
            try {
                var retorno = await _roleManager.CreateAsync(new Role { Name = roleDto.Name});

                return Ok(retorno);

            } catch (Exception error) {

                return this.StatusCode(StatusCodes.Status500InternalServerError, $"ERROR{error.Message}");
            }
        }

        [HttpPut("UpdateUserRole")]
        public async Task<IActionResult> UpdateUserRoles(UpdateUserRoleDto updateUserRoleDto) {
            try {
                var user = await _userManager.FindByEmailAsync(updateUserRoleDto.Email);

                if (user != null) {
                    if (updateUserRoleDto.Delete)
                        await _userManager.RemoveFromRoleAsync(user, updateUserRoleDto.Role);
                    else
                        await _userManager.AddToRoleAsync(user, updateUserRoleDto.Role);

                    return Ok("Success");

                } else {
                    return Ok("Usuário não encontrado");
                }

            } catch (Exception error) {

                return this.StatusCode(StatusCodes.Status500InternalServerError, $"ERROR{error.Message}");
            }
        }

        // POST api/<RoleController>
        [HttpPost]
        public void Post([FromBody] string value) {
        }

        // PUT api/<RoleController>/5
        [HttpPut("{id}")]
        public void Put(int id, [FromBody] string value) {
        }

        // DELETE api/<RoleController>/5
        [HttpDelete("{id}")]
        public void Delete(int id) {
        }
    }
}
