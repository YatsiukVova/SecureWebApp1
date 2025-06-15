// Controllers/DataController.cs
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace SecureWebApp.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    // Цей атрибут [Authorize] на рівні класу означає, що ВСІ методи в цьому контролері
    // вимагають, щоб користувач був автентифікований (залогінений).
    [Authorize]
    public class DataController : ControllerBase
    {
        // GET: api/data/public
        [HttpGet("public")]
        public IActionResult GetPublicData()
        {
            // Цей метод доступний для будь-якого користувача, який має валідний токен.
            // Ми можемо отримати ім'я користувача з "клеймів" токену.
            var currentUserName = User.Identity?.Name;

            return Ok($"Hello, {currentUserName}! This is public data, available to any authenticated user.");
        }

        // GET: api/data/admin
        [HttpGet("admin")]
        [Authorize(Roles = "Admin")] // Цей атрибут вимагає, щоб користувач мав роль "Admin".
        public IActionResult GetAdminData()
        {
            // Цей метод доступний тільки для адміністраторів.
            var currentUserName = User.Identity?.Name;
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier); // Приклад отримання ID користувача

            return Ok($"Welcome, Admin '{currentUserName}' (ID: {userId})! This is top-secret data.");
        }

        // GET: api/data/manager-or-admin
        [HttpGet("manager-or-admin")]
        [Authorize(Roles = "Admin,Manager")] // Кома тут працює як "АБО"
        public IActionResult GetManagerOrAdminData()
        {
            // Цей метод доступний для користувачів з роллю "Admin" АБО "Manager".
            return Ok("This data is for managers and admins only.");
        }
    }
}