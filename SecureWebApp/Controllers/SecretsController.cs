// Controllers/SecretsController.cs
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection; // Важливо додати цей using
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using SecureWebApp.Models;
using SecureWebApp.Models.DTO;
using System.Text;

namespace SecureWebApp.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize] // Весь контролер доступний тільки для залогінених користувачів
    public class SecretsController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IDataProtector _protector;

        // Впроваджуємо UserManager та IDataProtectionProvider
        public SecretsController(UserManager<ApplicationUser> userManager, IDataProtectionProvider provider)
        {
            _userManager = userManager;
            // Створюємо "протектор" з унікальною метою.
            // Це ізолює шифрування. Дані, зашифровані з однією метою, не можна розшифрувати з іншою.
            _protector = provider.CreateProtector("SecureWebApp.Secrets.v1");
        }

        // POST: api/secrets/save
        [HttpPost("save")]
        public async Task<IActionResult> SaveSecretNote([FromBody] SecretNoteModel model)
        {
            // Отримуємо поточного користувача
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return Unauthorized();
            }

            // Шифруємо нотатку
            // 1. Конвертуємо рядок у байти
            var noteBytes = Encoding.UTF8.GetBytes(model.Note);
            // 2. Шифруємо байти за допомогою протектора
            var encryptedNote = _protector.Protect(noteBytes);

            // Зберігаємо зашифровані дані
            user.SecretNote = encryptedNote;

            // Оновлюємо дані користувача в базі даних
            var result = await _userManager.UpdateAsync(user);

            if (result.Succeeded)
            {
                return Ok(new { Message = "Secret note saved successfully." });
            }

            return BadRequest(new { Message = "Failed to save secret note.", Errors = result.Errors });
        }


        // GET: api/secrets/retrieve
        [HttpGet("retrieve")]
        public async Task<IActionResult> RetrieveSecretNote()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                return Unauthorized();
            }

            if (user.SecretNote == null || user.SecretNote.Length == 0)
            {
                return Ok(new { Note = string.Empty, Message = "No secret note found." });
            }

            try
            {
                // Розшифровуємо дані
                var decryptedBytes = _protector.Unprotect(user.SecretNote);
                // Конвертуємо байти назад у рядок
                var decryptedNote = Encoding.UTF8.GetString(decryptedBytes);

                return Ok(new { Note = decryptedNote });
            }
            catch (System.Security.Cryptography.CryptographicException)
            {
                // Ця помилка виникне, якщо дані пошкоджені або ключ шифрування змінився
                return StatusCode(StatusCodes.Status500InternalServerError, new { Message = "Failed to decrypt the note. Data might be corrupted." });
            }
        }
    }
}