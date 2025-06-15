// Models/DTO/AddCardRequest.cs
using System.ComponentModel.DataAnnotations;

namespace SecureWebApp.Models.DTO
{
    public class AddCardRequest
    {
        [Required]
        public string CardholderName { get; set; }

        [Required]
        //[CreditCard] // Базова валідація формату номера картки
        public string CardNumber { get; set; }

        [Required]
        [RegularExpression(@"^(0[1-9]|1[0-2])\/?([0-9]{2})$", ErrorMessage = "Expiry date must be in MM/YY format")]
        public string ExpiryDate { get; set; }

        // Ми свідомо не додаємо поле CVV!
    }
}