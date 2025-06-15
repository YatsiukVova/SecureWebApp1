// Authorization/MfaRequiredRequirement.cs
using Microsoft.AspNetCore.Authorization;

namespace SecureWebApp.Authorization
{
    public class MfaRequiredRequirement : IAuthorizationRequirement
    {
        // Цей клас може бути порожнім. Він слугує лише як маркер
        // для нашої кастомної вимоги авторизації.
    }
}