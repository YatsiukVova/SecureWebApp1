// Models/DTO/VerifyMfaModel.cs
using System.ComponentModel.DataAnnotations;

namespace SecureWebApp.Models.DTO
{
    public class VerifyMfaModel
    {
        [Required]
        public string Code { get; set; }
    }
}