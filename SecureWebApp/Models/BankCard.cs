// Models/BankCard.cs
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace SecureWebApp.Models
{
    public class BankCard
    {
        [Key] // Первинний ключ
        public int Id { get; set; }

        [Required]
        public string CardholderName { get; set; }

        // Шифровані дані ми зберігаємо як масив байтів
        [Required]
        public byte[] EncryptedCardNumber { get; set; }

        [Required]
        public byte[] EncryptedExpiryDate { get; set; }

        // Для відображення користувачу (напр. ".... 1234") - зберігаємо відкрито
        [Required]
        [MaxLength(4)]
        public string Last4Digits { get; set; }

        // --- Зв'язок з користувачем (Зовнішній ключ) ---
        [Required]
        public string UserId { get; set; }

        [ForeignKey("UserId")]
        public virtual ApplicationUser User { get; set; }
        // ---------------------------------------------
    }
}