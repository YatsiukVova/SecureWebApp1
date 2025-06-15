// Authorization/MfaRequiredHandler.cs
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using SecureWebApp.Models;
using System.Threading.Tasks;

namespace SecureWebApp.Authorization
{
    public class MfaRequiredHandler : AuthorizationHandler<MfaRequiredRequirement>
    {
        private readonly UserManager<ApplicationUser> _userManager;

        public MfaRequiredHandler(UserManager<ApplicationUser> userManager)
        {
            _userManager = userManager;
        }

        protected override async Task HandleRequirementAsync(
            AuthorizationHandlerContext context,
            MfaRequiredRequirement requirement)
        {
            // Отримуємо поточного користувача з контексту
            var user = await _userManager.GetUserAsync(context.User);

            // Якщо користувача не знайдено, виходимо
            if (user == null)
            {
                return;
            }

            // Головна перевірка: чи увімкнено для користувача 2FA?
            if (user.TwoFactorEnabled)
            {
                // Якщо так, то вимога виконана. Повідомляємо систему авторизації.
                context.Succeed(requirement);
            }

            // Якщо вимога не виконана (user.TwoFactorEnabled == false), ми нічого не робимо.
            // Framework розцінить це як невдачу, оскільки context.Succeed не був викликаний.
        }
    }
}