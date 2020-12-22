using LoginAndRegistrationUsingJWTAndAPI.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace LoginAndRegistrationUsingJWTAndAPI.Controllers
{
    public class AccountController : ControllerBase
    {

        [HttpGet]
        public IActionResult Index()
        {
            return new ObjectResult(new { Message = "Hi You Reach Home Page" });
        }

        [Authorize]
        [HttpGet]
        public IActionResult privateAPI()
        {
            return new ObjectResult(new { Message = "you have reached the privateAPI" });
        }

        [HttpPost]
        public IActionResult Login(string userName, string password)
        {
            User login = new User()
            {
                UserName = userName,
                Password = password
            };

            IActionResult response = Unauthorized(new { Message = "User Doesn't Exist" });

            var user = AuthenticateUser(login);
            if (user != null)
            {
                var tokenString = GenerateJSONWebToken(user);
                response = Ok(new { userName = "Nour", token = tokenString });
            }
            return response;
        }

        private string GenerateJSONWebToken(User user)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("My Divine And Infinite Love"));
            var sigingCredentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var claims = new List<Claim>()
            {
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(ClaimTypes.Email, user.EmailAddress),
                new Claim(JwtRegisteredClaimNames.Nbf, new DateTimeOffset(DateTime.Now).ToUnixTimeSeconds().ToString()),
                new Claim(JwtRegisteredClaimNames.Exp, new DateTimeOffset(DateTime.Now.AddDays(1)).ToUnixTimeSeconds().ToString())
            };

            var jwtPayLoads = new JwtPayload(claims);

            var jwtHeader = new JwtHeader(sigingCredentials);

            var token = new JwtSecurityToken(jwtHeader, jwtPayLoads);

            var encodedToken = new JwtSecurityTokenHandler().WriteToken(token);

            return encodedToken;
        }

        private User AuthenticateUser(User login)
        {
            User superUser = null;
            if (login.UserName == "nour" && login.Password == "123")
            {
                superUser = new User()
                {
                    UserName = login.UserName,
                    Password = login.Password,
                    EmailAddress = "nour@nour.com"
                };
            }
            return superUser;
        }
    }
}
