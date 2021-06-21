using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace WebApplicationAuth
{
    public class AccountController : Controller
    {

        // тестовые данные вместо использования базы данных
        private List<User> people = new List<User>
        {
            new User {Login="admin@gmail.com", Password="12345", Role = "admin" },
            new User { Login="qwerty@gmail.com", Password="55555", Role = "user" }
        };


        [HttpGet("/me")]
        public string GetMe()
        {
            return HttpContext.User.Identity.Name;
        }


        [HttpPost("/token")]
        public IActionResult Token(string username, string password)
        {
            var identity = GetIdentity(username, password);
            if (identity == null)
            {
                return BadRequest(new { errorText = "Invalid username or password." });
            }

            var now = DateTime.UtcNow;
            // создаем JWT-токен
            var jwt = new JwtSecurityToken(
                    issuer: AuthOptions.Issuer,
                    audience: AuthOptions.Audience,
                    notBefore: now,
                    claims: identity.Claims,
                    expires: now.Add(TimeSpan.FromMinutes(AuthOptions.TokenLifetime)),
                    signingCredentials: new SigningCredentials(AuthOptions.GetSymmetricSecurityKey(), SecurityAlgorithms.HmacSha256));
            var encodedJwt = new JwtSecurityTokenHandler().WriteToken(jwt);

            var response = new
            {
                accessToken = encodedJwt,
                username = identity.Name
            };

            return Json(response);
        }


        [HttpPost("/token/validate")]
        public void ValidateToken(string authToken)
        {
            var tokenHandler = new JwtSecurityTokenHandler();

            var validationParameters = TokenHelper.GetJwtValidationParameters();

            var principal = tokenHandler.ValidateToken(
                 authToken,
                 validationParameters,
                out var validatedToken);
        }

        [Route("google-login")]
        public IActionResult GoogleLogin()
        {
            var properties = new AuthenticationProperties
            {
                RedirectUri = "http://localhost:5000",// Url.Action("GoogleResponse")
            };
            return Challenge(properties, GoogleDefaults.AuthenticationScheme);
        }

        [Route("google-response")]
        public async Task<IActionResult> GoogleResponse()
        {
            var result = await HttpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);

            var claims = result.Principal.Identities
                .FirstOrDefault().Claims.Select(claim => new
                {
                    claim.Issuer,
                    claim.OriginalIssuer,
                    claim.Type,
                    claim.Value
                });

            return Json(claims);
        }

        [Authorize(Roles = "admin", AuthenticationSchemes = "Bearer")]
        [HttpGet("/check-auth")]
        public string CheckAuthorize()
        {
            return "Проверка связи";
        }

        [HttpGet("me-win")]
        public string WhoAmIAsWin()
        {
            return HttpContext.User?.Identity?.Name;
        }


        private ClaimsIdentity GetIdentity(string username, string password)
        {
            User user = people.FirstOrDefault(x => x.Login == username && x.Password == password);
            if (user != null)
            {
                var claims = new List<Claim>
                {
                    new Claim(ClaimsIdentity.DefaultNameClaimType, user.Login),
                    new Claim(ClaimsIdentity.DefaultRoleClaimType, user.Role),
                    new Claim("Age", "29"),
                };
                var claimsIdentity = new ClaimsIdentity(
                                        claims,
                                        "Token",
                                        ClaimsIdentity.DefaultNameClaimType,
                                        ClaimsIdentity.DefaultRoleClaimType);
                return claimsIdentity;
            }

            // если пользователя не найдено
            return null;
        }
    }
}
