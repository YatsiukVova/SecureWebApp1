// Controllers/CardsController.cs
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SecureWebApp.Data;
using SecureWebApp.Models;
using SecureWebApp.Models.DTO;
using System.Security.Claims;
using System.Text;

[Route("api/[controller]")]
[ApiController]
[Authorize(Policy = "MfaRequiredPolicy")] // Весь контролер вимагає авторизації
public class CardsController : ControllerBase
{
    private readonly ApplicationDbContext _context;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IDataProtector _protector;

    public CardsController(ApplicationDbContext context, UserManager<ApplicationUser> userManager, IDataProtectionProvider provider)
    {
        _context = context;
        _userManager = userManager;
        // Створюємо протектор з новою, унікальною метою для карток
        _protector = provider.CreateProtector("SecureWebApp.BankCards.v1");
    }

    // POST: api/cards/add
    [HttpPost("add")]
    public async Task<IActionResult> AddCard([FromBody] AddCardRequest model)
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (userId == null) return Unauthorized();

        // Шифруємо чутливі дані
        var encryptedCardNumber = _protector.Protect(Encoding.UTF8.GetBytes(model.CardNumber));
        var encryptedExpiryDate = _protector.Protect(Encoding.UTF8.GetBytes(model.ExpiryDate));

        var newCard = new BankCard
        {
            UserId = userId,
            CardholderName = model.CardholderName,
            EncryptedCardNumber = encryptedCardNumber,
            EncryptedExpiryDate = encryptedExpiryDate,
            // Зберігаємо тільки останні 4 цифри для відображення
            Last4Digits = model.CardNumber.Substring(model.CardNumber.Length - 4)
        };

        _context.BankCards.Add(newCard);
        await _context.SaveChangesAsync();

        return Ok(new { Message = "Bank card added successfully." });
    }

    // GET: api/cards/my-cards
    [HttpGet("my-cards")]
    public async Task<IActionResult> GetMyCards()
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (userId == null) return Unauthorized();

        // Отримуємо список карток користувача з БД
        var cards = await _context.BankCards
                                  .Where(c => c.UserId == userId)
                                  .Select(c => new CardViewModel // Проектуємо в безпечну модель
                                  {
                                      Id = c.Id,
                                      CardholderName = c.CardholderName,
                                      MaskedCardNumber = $"**** **** **** {c.Last4Digits}"
                                  })
                                  .ToListAsync();

        return Ok(cards);
    }

    // GET: api/cards/{id}/details - отримання розшифрованих даних
    [HttpGet("{id}/details")]
    public async Task<IActionResult> GetCardDetails(int id)
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (userId == null) return Unauthorized();

        // Знаходимо картку за ID, перевіряючи, що вона належить поточному користувачу
        var card = await _context.BankCards.FirstOrDefaultAsync(c => c.Id == id && c.UserId == userId);

        if (card == null)
        {
            return NotFound(new { Message = "Card not found or you don't have access to it." });
        }

        try
        {
            // Розшифровуємо дані
            var decryptedCardNumber = Encoding.UTF8.GetString(_protector.Unprotect(card.EncryptedCardNumber));
            var decryptedExpiryDate = Encoding.UTF8.GetString(_protector.Unprotect(card.EncryptedExpiryDate));

            // Повертаємо розшифровані дані (тільки в цьому ендпоінті!)
            return Ok(new
            {
                CardholderName = card.CardholderName,
                CardNumber = decryptedCardNumber,
                ExpiryDate = decryptedExpiryDate
            });
        }
        catch (Exception)
        {
            return StatusCode(500, new { Message = "Failed to decrypt card details." });
        }
    }
}