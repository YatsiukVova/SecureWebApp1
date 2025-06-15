// Models/DTO/LoginMfaModel.cs
using System.ComponentModel.DataAnnotations;

namespace SecureWebApp.Models.DTO
{
    public class LoginMfaModel
    {
        [Required]
        public string Username { get; set; }

        [Required]
        public string Code { get; set; }
    }
}