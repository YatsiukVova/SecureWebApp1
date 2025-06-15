// Program.cs
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models; // ��� ����������� Swagger JWT
using SecureWebApp.Authorization;
using SecureWebApp.Data;
using SecureWebApp.Models; // �������, ���� �������� ApplicationUser
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// 1. ������������ DbContext
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(connectionString));

// 2. ������������ ASP.NET Core Identity
builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
{
    // ������������ ������
    options.Password.RequireDigit = true;
    options.Password.RequiredLength = 8;
    options.Password.RequireNonAlphanumeric = true; // �������� ����������
    options.Password.RequireUppercase = true;
    options.Password.RequireLowercase = true;
    options.Password.RequiredUniqueChars = 1; // ʳ������ ��������� ������� � �����

    // ������������ ���������� ����������� (Lockout settings)
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5); // ��� ����������
    options.Lockout.MaxFailedAccessAttempts = 5; // ʳ������ �������� ����� ����� �����������
    options.Lockout.AllowedForNewUsers = true;

    // ������������ ����������� (User settings)
    options.User.AllowedUserNameCharacters =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@+"; // �������� ������� � ���� �����������
    options.User.RequireUniqueEmail = true; // �������� ��������� Email

    // ������������ ����� (SignIn settings)
    options.SignIn.RequireConfirmedEmail = false; // ��� �������� ����� ��������, ��� ���������� ������ true
    options.SignIn.RequireConfirmedPhoneNumber = false; // ���������
})
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders(); // ������������� ������ ��� �������� ������, 2FA ����.

// 3. ������������ JWT-��������������
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
})
    .AddJwtBearer(options =>
    {
        options.SaveToken = true; // �������� ����� � HttpContext.Authentication.AuthenticateResult
        options.RequireHttpsMetadata = builder.Environment.IsProduction(); // �������� HTTPS ��� ��������� ������ � ���������
        options.TokenValidationParameters = new TokenValidationParameters()
        {
            ValidateIssuer = true, // ��������� ������� ������
            ValidateAudience = true, // ��������� ���������� ������
            ValidateLifetime = true, // ��������� ��� ����� ������
            ValidateIssuerSigningKey = true, // ��������� ���� ������ �������

            ValidIssuer = builder.Configuration["JWT:ValidIssuer"],
            ValidAudience = builder.Configuration["JWT:ValidAudience"],
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["JWT:Secret"]!)) // �������������� ! ��� ���������� ������������ ��� null, ���� �������, �� �������� ����
        };
    });

builder.Services.AddScoped<IAuthorizationHandler, MfaRequiredHandler>(); // �������� ��������

builder.Services.AddAuthorization(options =>
{
    // ������ ���� ������� � ������ "MfaRequiredPolicy"
    options.AddPolicy("MfaRequiredPolicy", policy =>
        policy.AddRequirements(new MfaRequiredRequirement()));

    // ��� ����� �������� � ���� ������� � �����������
    // options.AddPolicy("AnotherPolicy", ...);
});

builder.Services.AddControllers();

// ������������ Swagger/OpenAPI ��� �������� JWT
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo { Title = "SecureWebApp API", Version = "v1" });

    // ������ ���������� ������� ��� JWT
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
        context.Database.Migrate(); // ��������� ����-�� �������� ������� ��� ��������� �� ���� �����. �������� ���� �����, ���� ���� �� �� ����.

        // ��� ����� ������ ��� ��� ����������� ���������� �� ������ (seeding), ���������, ��������� �����
        // await SeedRolesAsync(services); // ������� ������� ������ ��� ����������� ���������� �����
    }
    catch (Exception ex)
    {
        var logger = services.GetRequiredService<ILogger<Program>>();
        logger.LogError(ex, "An error occurred while migrating or initializing the database.");
        // ���������� ��������� ������� ��������, ���� �� � ���������
    }
}


// ������ ������� HTTP-������ (Middleware pipeline)
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(c =>
    {
        c.SwaggerEndpoint("/swagger/v1/swagger.json", "SecureWebApp API V1");
        // ����� ������ ���� ������������ UI, ���������:
        // c.RoutePrefix = string.Empty; // ��� Swagger UI ��� ��������� �� ��������� URL
    });
    app.UseDeveloperExceptionPage(); // ����� ������� ������� ��� ��������
}
else
{
    app.UseExceptionHandler("/Error"); // �������� ������� ������� ��� ����������
    app.UseHsts(); // ���� ��������� Strict-Transport-Security
}

app.UseHttpsRedirection(); // ��������������� HTTP �� HTTPS (������� ��� �������!)

app.UseRouting(); // ���� ������������� �� �������

app.UseAuthentication(); // ����� �������� ��������������. �� ���� �� UseAuthorization.
app.UseAuthorization(); // ����� �������� �����������.

app.MapControllers(); // ������ ������ �� �� ����������

app.Run();

// ������� ������ ��� ����������� ���������� ����� (seeding) - ����� ��������� � ���� Program.cs ��� ������� � ������� ����
/*
async Task SeedRolesAsync(IServiceProvider serviceProvider)
{
    var roleManager = serviceProvider.GetRequiredService<RoleManager<IdentityRole>>();
    string[] roleNames = { "Admin", "User", "Manager" }; // ���� ���

    foreach (var roleName in roleNames)
    {
        var roleExist = await roleManager.RoleExistsAsync(roleName);
        if (!roleExist)
        {
            // ��������� ����
            await roleManager.CreateAsync(new IdentityRole(roleName));
        }
    }
}
*/