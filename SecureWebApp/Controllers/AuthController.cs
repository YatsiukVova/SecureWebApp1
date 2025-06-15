// Controllers/AuthController.cs
using Microsoft.AspNetCore.Authorization; // Додайте цей using
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using SecureWebApp.Models;
using SecureWebApp.Models.DTO;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web; // Додайте цей using для UrlEncoder

namespace SecureWebApp.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize] // Всі ендпоінти вимагають авторизації за замовчуванням
    public class AuthController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;
        private readonly UrlEncoder _urlEncoder;

        public AuthController(
            UserManager<ApplicationUser> userManager,
            RoleManager<IdentityRole> roleManager,
            IConfiguration configuration,
            UrlEncoder urlEncoder) // Додаємо UrlEncoder для генерації URI
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
            _urlEncoder = urlEncoder;
        }

        // POST: api/auth/login
        [HttpPost("login")]
        [AllowAnonymous] // Дозволяємо анонімний доступ до цього методу
        public async Task<IActionResult> Login([FromBody] LoginModel model)
        {
            var user = await _userManager.FindByNameAsync(model.Username);
            if (user != null && await _userManager.CheckPasswordAsync(user, model.Password))
            {
                // --- ЗМІНА ТУТ: Перевіряємо, чи увімкнено MFA ---
                if (await _userManager.GetTwoFactorEnabledAsync(user))
                {
                    // Якщо так, не видаємо токен, а вимагаємо другий фактор
                    return Ok(new { IsTwoFactorRequired = true, Message = "Two-factor authentication is required." });
                }
                // ---------------------------------------------

                var tokenDetails = await GenerateJwtToken(user);
                return Ok(new LoginResponse { Token = tokenDetails.Token, Expiration = tokenDetails.Expiration });
            }
            return Unauthorized(new { Message = "Invalid username or password" });
        }

        // --- НОВИЙ ЕНДПОІНТ для входу з кодом MFA ---
        // POST: api/auth/login-mfa
        [HttpPost("login-mfa")]
        [AllowAnonymous]
        public async Task<IActionResult> LoginMfa([FromBody] LoginMfaModel model)
        {
            var user = await _userManager.FindByNameAsync(model.Username);
            if (user == null)
            {
                return Unauthorized(new { Message = "Invalid username or code." });
            }

            // Перевіряємо код з автентифікатора
            var isValid = await _userManager.VerifyTwoFactorTokenAsync(user, _userManager.Options.Tokens.AuthenticatorTokenProvider, model.Code);

            if (isValid)
            {
                var tokenDetails = await GenerateJwtToken(user);
                return Ok(new LoginResponse { Token = tokenDetails.Token, Expiration = tokenDetails.Expiration });
            }

            return Unauthorized(new { Message = "Invalid username or code." });
        }
        // ---------------------------------------------


        // POST: api/auth/register
        [HttpPost("register")]
        [AllowAnonymous]
        public async Task<IActionResult> Register([FromBody] RegisterModel model)
        {
            var userExists = await _userManager.FindByNameAsync(model.Username);
            if (userExists != null)
                return StatusCode(StatusCodes.Status409Conflict, new { Status = "Error", Message = "User already exists!" });

            ApplicationUser user = new()
            {
                Email = model.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = model.Username
            };

            var result = await _userManager.CreateAsync(user, model.Password);
            if (!result.Succeeded)
            {
                var errors = result.Errors.Select(e => e.Description);
                return StatusCode(StatusCodes.Status500InternalServerError, new { Status = "Error", Message = "User creation failed! Errors: " + string.Join(", ", errors) });
            }

            if (!await _roleManager.RoleExistsAsync("User"))
                await _roleManager.CreateAsync(new IdentityRole("User"));
            if (await _roleManager.RoleExistsAsync("User"))
                await _userManager.AddToRoleAsync(user, "User");

            return Ok(new { Status = "Success", Message = "User created successfully!" });
        }

        // POST: api/auth/register-admin
        [HttpPost("register-admin")]
        [AllowAnonymous] // Зробимо його анонімним для простоти тестування
        public async Task<IActionResult> RegisterAdmin([FromBody] RegisterModel model)
        {
            var userExists = await _userManager.FindByNameAsync(model.Username);
            if (userExists != null)
                return StatusCode(StatusCodes.Status409Conflict, new { Status = "Error", Message = "User already exists!" });

            ApplicationUser user = new()
            {
                Email = model.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = model.Username
            };
            var result = await _userManager.CreateAsync(user, model.Password);
            if (!result.Succeeded)
            {
                var errors = result.Errors.Select(e => e.Description);
                return StatusCode(StatusCodes.Status500InternalServerError, new { Status = "Error", Message = "User creation failed! Errors: " + string.Join(", ", errors) });
            }

            if (!await _roleManager.RoleExistsAsync("Admin"))
                await _roleManager.CreateAsync(new IdentityRole("Admin"));

            await _userManager.AddToRoleAsync(user, "Admin");

            return Ok(new { Status = "Success", Message = "Admin user created successfully!" });
        }

        // --- НОВІ ЕНДПОІНТИ ДЛЯ КЕРУВАННЯ MFA ---
        // POST: api/auth/enable-mfa
        [HttpPost("enable-mfa")]
        // [Authorize] вже діє на рівні контролера
        public async Task<IActionResult> EnableMfa()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null) return Unauthorized();

            // Генеруємо ключ для автентифікатора
            var unformattedKey = await _userManager.GetAuthenticatorKeyAsync(user);
            if (string.IsNullOrEmpty(unformattedKey))
            {
                await _userManager.ResetAuthenticatorKeyAsync(user);
                unformattedKey = await _userManager.GetAuthenticatorKeyAsync(user);
            }

            var sharedKey = unformattedKey; // Для відображення користувачу

            // Генеруємо URI для QR-коду
            var authenticatorUri = $"otpauth://totp/{_urlEncoder.Encode("SecureWebApp")}:{_urlEncoder.Encode(user.Email)}?secret={unformattedKey}&issuer={_urlEncoder.Encode("SecureWebApp")}";

            return Ok(new EnableMfaResponse
            {
                SharedKey = sharedKey,
                AuthenticatorUri = authenticatorUri
            });
        }

        // POST: api/auth/verify-mfa
        [HttpPost("verify-mfa")]
        public async Task<IActionResult> VerifyMfa([FromBody] VerifyMfaModel model)
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null) return Unauthorized();

            // Перевіряємо код, наданий користувачем
            var is2faTokenValid = await _userManager.VerifyTwoFactorTokenAsync(
                user, _userManager.Options.Tokens.AuthenticatorTokenProvider, model.Code);

            if (!is2faTokenValid)
            {
                return BadRequest(new { Message = "Verification code is invalid." });
            }

            // Якщо код валідний, вмикаємо MFA для користувача
            await _userManager.SetTwoFactorEnabledAsync(user, true);

            return Ok(new { Status = "Success", Message = "MFA has been enabled successfully." });
        }
        // ----------------------------------------

        // Приватний метод для генерації JWT токену (без змін)
        private async Task<(string Token, DateTime Expiration)> GenerateJwtToken(ApplicationUser user)
        {
            var userRoles = await _userManager.GetRolesAsync(user);
            var authClaims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.UserName!),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(ClaimTypes.NameIdentifier, user.Id)
            };
            foreach (var userRole in userRoles)
            {
                authClaims.Add(new Claim(ClaimTypes.Role, userRole));
            }
            var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]!));
            var tokenValidTo = DateTime.UtcNow.AddHours(3);
            var token = new JwtSecurityToken(
                issuer: _configuration["JWT:ValidIssuer"],
                audience: _configuration["JWT:ValidAudience"],
                expires: tokenValidTo,
                claims: authClaims,
                signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
            );
            return (new JwtSecurityTokenHandler().WriteToken(token), tokenValidTo);
        }
    }
}