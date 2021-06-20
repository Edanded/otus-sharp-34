using Microsoft.IdentityModel.Tokens;

namespace WebApplicationAuth
{
    public static class TokenHelper
    {
        /// <summary>
        /// Параметры валидации JWT-токена
        /// </summary>
        /// <returns></returns>
        public static TokenValidationParameters GetJwtValidationParameters()
        => new TokenValidationParameters
        {
            // Проверять того, кто издал токен
            ValidateIssuer = true,
            // Издатель
            ValidIssuer = AuthOptions.Issuer,

            // Проверять аудиторию
            ValidateAudience = true,
            // Проверять аудиторию
            ValidAudience = AuthOptions.Audience,
            // Проверять время жизни
            ValidateLifetime = true,

            // Подпись
            IssuerSigningKey = AuthOptions.GetSymmetricSecurityKey(),
            // Проверять подпись
            ValidateIssuerSigningKey = true,
        };
    }
}