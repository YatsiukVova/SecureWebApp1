// Program.cs
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models; // Для налаштувань Swagger JWT
using SecureWebApp.Authorization;
using SecureWebApp.Data;
using SecureWebApp.Models; // Додайте, якщо створили ApplicationUser
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// 1. Конфігурація DbContext
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(connectionString));

// 2. Конфігурація ASP.NET Core Identity
builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
{
    // Налаштування пароля
    options.Password.RequireDigit = true;
    options.Password.RequiredLength = 8;
    options.Password.RequireNonAlphanumeric = true; // Вимагати спецсимвол
    options.Password.RequireUppercase = true;
    options.Password.RequireLowercase = true;
    options.Password.RequiredUniqueChars = 1; // Кількість унікальних символів у паролі

    // Налаштування блокування користувача (Lockout settings)
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5); // Час блокування
    options.Lockout.MaxFailedAccessAttempts = 5; // Кількість невдалих спроб перед блокуванням
    options.Lockout.AllowedForNewUsers = true;

    // Налаштування користувача (User settings)
    options.User.AllowedUserNameCharacters =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@+"; // Дозволені символи в імені користувача
    options.User.RequireUniqueEmail = true; // Вимагати унікальний Email

    // Налаштування входу (SignIn settings)
    options.SignIn.RequireConfirmedEmail = false; // Для розробки можна вимкнути, для продакшену бажано true
    options.SignIn.RequireConfirmedPhoneNumber = false; // Аналогічно
})
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders(); // Постачальники токенів для скидання пароля, 2FA тощо.

// 3. Конфігурація JWT-автентифікації
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
})
    .AddJwtBearer(options =>
    {
        options.SaveToken = true; // Зберігати токен в HttpContext.Authentication.AuthenticateResult
        options.RequireHttpsMetadata = builder.Environment.IsProduction(); // Вимагати HTTPS для метаданих токена в продакшені
        options.TokenValidationParameters = new TokenValidationParameters()
        {
            ValidateIssuer = true, // Перевіряти видавця токена
            ValidateAudience = true, // Перевіряти отримувача токена
            ValidateLifetime = true, // Перевіряти час життя токена
            ValidateIssuerSigningKey = true, // Перевіряти ключ підпису видавця

            ValidIssuer = builder.Configuration["JWT:ValidIssuer"],
            ValidAudience = builder.Configuration["JWT:ValidAudience"],
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["JWT:Secret"]!)) // Використовуйте ! для подавлення попередження про null, якщо впевнені, що значення буде
        };
    });

builder.Services.AddScoped<IAuthorizationHandler, MfaRequiredHandler>(); // Реєструємо обробник

builder.Services.AddAuthorization(options =>
{
    // Додаємо нову політику з іменем "MfaRequiredPolicy"
    options.AddPolicy("MfaRequiredPolicy", policy =>
        policy.AddRequirements(new MfaRequiredRequirement()));

    // Тут можна додавати й інші політики в майбутньому
    // options.AddPolicy("AnotherPolicy", ...);
});

builder.Services.AddControllers();

// Налаштування Swagger/OpenAPI для підтримки JWT
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo { Title = "SecureWebApp API", Version = "v1" });

    // Додаємо визначення безпеки для JWT
    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Description = @"JWT Authorization header using the Bearer scheme. 
                      Enter 'Bearer' [space] and then your token in the text input below.
                      Example: 'Bearer 12345abcdef'",
        Name = "Authorization",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.ApiKey,
        Scheme = "Bearer"
    });

    c.AddSecurityRequirement(new OpenApiSecurityRequirement()
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                },
                Scheme = "oauth2",
                Name = "Bearer",
                In = ParameterLocation.Header,
            },
            new List<string>()
        }
    });
});


var app = builder.Build();

using (var scope = app.Services.CreateScope())
{
    var services = scope.ServiceProvider;
    try
    {
        var context = services.GetRequiredService<ApplicationDbContext>();
        context.Database.Migrate(); // Застосовує будь-які очікуючі міграції для контексту до бази даних. Створить базу даних, якщо вона ще не існує.

        // Тут можна додати код для початкового заповнення БД даними (seeding), наприклад, створення ролей
        // await SeedRolesAsync(services); // Приклад виклику методу для початкового заповнення ролей
    }
    catch (Exception ex)
    {
        var logger = services.GetRequiredService<ILogger<Program>>();
        logger.LogError(ex, "An error occurred while migrating or initializing the database.");
        // Розгляньте можливість зупинки програми, якщо БД є критичною
    }
}


// Конвеєр обробки HTTP-запитів (Middleware pipeline)
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(c =>
    {
        c.SwaggerEndpoint("/swagger/v1/swagger.json", "SecureWebApp API V1");
        // Можна додати інші налаштування UI, наприклад:
        // c.RoutePrefix = string.Empty; // Щоб Swagger UI був доступний за кореневим URL
    });
    app.UseDeveloperExceptionPage(); // Більш детальні помилки для розробки
}
else
{
    app.UseExceptionHandler("/Error"); // Загальна сторінка помилок для продакшену
    app.UseHsts(); // Додає заголовок Strict-Transport-Security
}

app.UseHttpsRedirection(); // Перенаправлення HTTP на HTTPS (важливо для безпеки!)

app.UseRouting(); // Додає маршрутизацію до конвеєра

app.UseAuthentication(); // Вмикає механізми автентифікації. Має бути ДО UseAuthorization.
app.UseAuthorization(); // Вмикає механізми авторизації.

app.MapControllers(); // Мапить запити до дій контролерів

app.Run();

// Приклад методу для початкового заповнення ролей (seeding) - можна розмістити в кінці Program.cs або винести в окремий клас
/*
async Task SeedRolesAsync(IServiceProvider serviceProvider)
{
    var roleManager = serviceProvider.GetRequiredService<RoleManager<IdentityRole>>();
    string[] roleNames = { "Admin", "User", "Manager" }; // Ваші ролі

    foreach (var roleName in roleNames)
    {
        var roleExist = await roleManager.RoleExistsAsync(roleName);
        if (!roleExist)
        {
            // створюємо роль
            await roleManager.CreateAsync(new IdentityRole(roleName));
        }
    }
}
*/