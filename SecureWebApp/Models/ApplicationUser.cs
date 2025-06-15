using Microsoft.AspNetCore.Identity;

namespace SecureWebApp.Models
{
    public class ApplicationUser : IdentityUser
    {
        public byte[]? SecretNote { get; set; }
        // ������� �������� ���������� ����������� �� �������
    }
}