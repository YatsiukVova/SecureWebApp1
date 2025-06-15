// Models/DTO/CardViewModel.cs
namespace SecureWebApp.Models.DTO
{
    public class CardViewModel
    {
        public int Id { get; set; }
        public string CardholderName { get; set; }
        public string MaskedCardNumber { get; set; } // Напр. "**** **** **** 1234"
    }
}