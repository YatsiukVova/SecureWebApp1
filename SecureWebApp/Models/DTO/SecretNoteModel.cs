// Models/DTO/SecretNoteModel.cs
using System.ComponentModel.DataAnnotations;

namespace SecureWebApp.Models.DTO
{
    public class SecretNoteModel
    {
        [Required]
        [MaxLength(500)]
        public string Note { get; set; }
    }
}