// Models/DTO/LoginResponse.cs
namespace SecureWebApp.Models.DTO
{
    public class LoginResponse
    {
        public string Token { get; set; }
        public DateTime Expiration { get; set; }
    }
}