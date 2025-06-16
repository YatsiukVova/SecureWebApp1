# SecureWebApp: Демонстраційний проєкт для кваліфікаційної роботи

Цей проєкт є практичною реалізацією для кваліфікаційної роботи на тему **"Інтеграція сучасних методів безпеки у веб-додатках: автентифікація, шифрування та управління доступом"**.

Проєкт є веб-API, розробленим на ASP.NET Core 8, та демонструє комплексний підхід до захисту сучасних веб-додатків.

##  Реалізовані механізми безпеки

-   **Автентифікація:**
    -   Реалізована система реєстрації та входу користувачів на базі **ASP.NET Core Identity**.
    -   Використовується автентифікація на основі **JWT (JSON Web Tokens)** для захисту API.
-   **Багатофакторна автентифікація (MFA/2FA):**
    -   Інтегровано підтримку **TOTP (Time-based One-Time Password)** з використанням додатків-автентифікаторів (Google Authenticator, Authy тощо).
-   **Управління доступом (Авторизація):**
    -   Реалізовано **рольову модель доступу (RBAC)** з ролями "User" та "Admin".
    -   Створено **кастомну політику авторизації** (MfaRequiredPolicy), яка вимагає від користувача увімкненої MFA для доступу до критичних ендпоінтів (наприклад, керування банківськими картками).
-   **Шифрування:**
    -   **Шифрування даних під час передачі** забезпечується використанням **HTTPS**.
    -   **Шифрування даних у стані спокою** реалізовано на рівні додатку за допомогою **ASP.NET Core Data Protection API** для захисту чутливих даних (номери банківських карток) перед збереженням у базу даних.

## Технологічний стек

-   **Платформа:** .NET 8
-   **Фреймворк:** ASP.NET Core 8 Web API
-   **Робота з даними:** Entity Framework Core 8
-   **База даних:** Microsoft SQL Server (LocalDB)
-   **Автентифікація:** ASP.NET Core Identity, JWT Bearer
-   **Тестування API:** Swagger (OpenAPI)

## Налаштування та запуск

### Вимоги:

-   Visual Studio 2022 (або новіше) з робочим навантаженням "ASP.NET and web development".
-   .NET 8 SDK.
-   SQL Server Express LocalDB (зазвичай встановлюється разом з Visual Studio).

### Кроки для запуску:

1.  **Клонуйте репозиторій:**
    
bash
    git clone [https://github.com/YatsiukVova/SecureWebApp1.git](https://github.com/YatsiukVova/SecureWebApp1.git)
    cd SecureWebApp

2.  **Відкрийте проєкт** у Visual Studio, відкривши файл SecureWebApp.sln.

3.  **Налаштуйте appsettings.json:**
    -   Перевірте рядок підключення до бази даних у секції ConnectionStrings. Стандартний рядок для LocalDB вже налаштовано.
    -   У секції JWT вкажіть ваш ValidAudience, ValidIssuer (URL, на якому запускається додаток) та згенеруйте надійний Secret.

4.  **Створіть базу даних:**
    -   У Visual Studio відкрийте "Консоль диспетчера пакетів" (Tools -> NuGet Package Manager -> Package Manager Console).
    -   Виконайте команду:
        
powershell
       
    -    Update-Database
    
Ця команда створить базу даних та всі необхідні таблиці на основі існуючих міграцій.
5.  **Запустіть додаток:**
    -   Натисніть F5 або зелену кнопку "▶ SecureWebApp" у верхній панелі Visual Studio.
    -   Відкриється браузер зі сторінкою Swagger UI, де ви зможете тестувати API.
SecureWebApp/
│
├── 📂 Authorization/
│   ├── MfaRequiredHandler.cs      # Обробник, що перевіряє, чи увімкнено MFA
│   └── MfaRequiredRequirement.cs  # Клас-маркер для політики MFA
│
├── 📂 Controllers/
│   ├── AuthController.cs          # Керує реєстрацією, входом, MFA
│   ├── CardsController.cs         # Керує банківськими картками (з шифруванням)
│   └── DataController.cs          # Демонструє доступ за ролями
│
├── 📂 Data/
│   └── ApplicationDbContext.cs    # Контекст бази даних (EF Core)
│
├── 📂 Migrations/
│   └── ... (файли міграцій бази даних)
│
├── 📂 Models/
│   ├── DTO/                     # Data Transfer Objects
│   │   ├── AddCardRequest.cs
│   │   ├── CardViewModel.cs
│   │   ├── EnableMfaResponse.cs
│   │   ├── LoginMfaModel.cs
│   │   ├── LoginModel.cs
│   │   ├── LoginResponse.cs
│   │   ├── RegisterModel.cs
│   │   └── VerifyMfaModel.cs
│   │
│   ├── ApplicationUser.cs       # Розширена модель користувача Identity
│   └── BankCard.cs              # Модель банківської картки
│
├── 📂 Properties/
│   └── launchSettings.json      # Налаштування запуску проєкту
│
├── appsettings.json               # Конфігурація додатка (БД, JWT)
├── Program.cs                     # Головний файл (конфігурація сервісів, middleware)
└── SecureWebApp.csproj            # Файл проєкту (залежності, NuGet-пакети)
