using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JWT_sample.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        [AllowAnonymous]
        [HttpPost("login")]
        public IActionResult Login(string username, string password)
        {
            // اعتبارسنجی نام کاربری و رمز عبور (اینجا می‌توانید منطق اعتبارسنجی و احراز هویت خود را اضافه کنید)
            if (username == "YourUsername" && password == "YourPassword")
            {
                var token = GenerateJwtToken(username);
                return Ok(new { token });
            }

            return Unauthorized();
        }

        [Authorize]
        [HttpGet("protected")]
        public IActionResult ProtectedResource()
        {
            return Ok("This is a protected resource.");
        }

        private string GenerateJwtToken(string username)
        {
            var jwtSecret = "MySuperSecretKey"; // همان کلید مخفی که در Program.cs قرار داده‌ایم
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(jwtSecret);

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new Claim[]
                {
                    new Claim(ClaimTypes.Name, username)
                }),
                Expires = DateTime.UtcNow.AddHours(1),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }
    }
}
