// Models/DTO/EnableMfaResponse.cs
namespace SecureWebApp.Models.DTO
{
    public class EnableMfaResponse
    {
        public string SharedKey { get; set; }
        public string AuthenticatorUri { get; set; }
    }
}