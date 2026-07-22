using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using BankingAuth.Api.Data;
using BankingAuth.Api.Domain;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

var jwtKey = builder.Configuration["Jwt:SigningKey"];
if (string.IsNullOrWhiteSpace(jwtKey))
{
    if (!builder.Environment.IsDevelopment())
        throw new InvalidOperationException(
            "Jwt:SigningKey must be configured via configuration or the Jwt__SigningKey environment variable outside Development.");

    // Dev-only fallback so `dotnet run` works without extra setup. Never used outside Development
    // because appsettings.json (Production/shared) intentionally omits Jwt:SigningKey.
    jwtKey = "dev-only-change-me-banking-auth-signing-key-32b!";
}

var contentRootPath = builder.Environment.ContentRootPath;

builder.Services.AddOpenApi();
builder.Services.AddDbContext<AuthDbContext>((sp, options) =>
{
    // Resolved from DI (not the top-level `builder.Configuration`) so that test-only overrides
    // registered via WebApplicationFactory.ConfigureWebHost - which are applied when the host is
    // built, after this file's top-level statements start running - are honored.
    var configuration = sp.GetRequiredService<IConfiguration>();
    var connectionString = configuration.GetConnectionString("BankingAuthDb") ?? "Data Source=bankingauth.db";
    options.UseSqlite(ResolveSqliteConnectionString(connectionString, contentRootPath));
});
builder.Services.AddScoped(sp => new AuthService(sp.GetRequiredService<AuthDbContext>(), jwtKey));
builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateIssuerSigningKey = true,
            ValidateLifetime = true,
            ValidIssuer = "BankingAuthService",
            ValidAudience = "banking-clients",
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey))
        };
    });
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("AdminOnly", policy => policy.RequireRole(nameof(UserRole.Admin)));
});

var app = builder.Build();

using (var startupScope = app.Services.CreateScope())
{
    var db = startupScope.ServiceProvider.GetRequiredService<AuthDbContext>();
    db.Database.EnsureCreated();
    db.Database.ExecuteSqlRaw("PRAGMA journal_mode='WAL';");

    var adminEmail = builder.Configuration["Admin:Email"] ?? "admin@example.com";
    var adminPassword = builder.Configuration["Admin:Password"] ?? "Admin123!";
    startupScope.ServiceProvider.GetRequiredService<AuthService>().EnsureAdmin(adminEmail, adminPassword);
}

app.Use(async (context, next) =>
{
    context.Response.Headers["X-Content-Type-Options"] = "nosniff";
    context.Response.Headers["X-Frame-Options"] = "DENY";
    context.Response.Headers["Referrer-Policy"] = "no-referrer";
    context.Response.Headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'";
    await next();
});

app.MapOpenApi();

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/", () => Results.Redirect("/openapi/v1.json"));

app.MapPost("/api/auth/register", (RegisterRequest request, AuthService auth) =>
{
    try
    {
        var user = auth.Register(request);
        return Results.Created("/api/me", new { user.UserId, user.Email, role = user.Role.ToString() });
    }
    catch (InvalidOperationException ex)
    {
        return Results.BadRequest(new { error = ex.Message });
    }
});

app.MapPost("/api/auth/login", (LoginRequest request, AuthService auth) =>
{
    try
    {
        return Results.Ok(auth.Login(request));
    }
    catch (UnauthorizedAccessException)
    {
        return Results.Unauthorized();
    }
});

app.MapPost("/api/auth/refresh", (RefreshRequest request, AuthService auth) =>
{
    try
    {
        return Results.Ok(auth.Refresh(request.RefreshToken));
    }
    catch (UnauthorizedAccessException)
    {
        return Results.Unauthorized();
    }
});

app.MapPost("/api/auth/logout", (LogoutRequest request, AuthService auth) =>
{
    try
    {
        auth.Logout(request.RefreshToken);
        return Results.NoContent();
    }
    catch (UnauthorizedAccessException)
    {
        return Results.Unauthorized();
    }
});

app.MapPost("/api/auth/totp/setup", (ClaimsPrincipal principal, AuthService auth) =>
{
    var userId = ResolveUserId(principal);
    if (userId is null)
        return Results.Unauthorized();

    return Results.Ok(auth.BeginEnableTotp(userId));
}).RequireAuthorization();

app.MapPost("/api/auth/totp/confirm", (VerifyTotpRequest request, ClaimsPrincipal principal, AuthService auth) =>
{
    var userId = ResolveUserId(principal);
    if (userId is null)
        return Results.Unauthorized();

    try
    {
        auth.ConfirmEnableTotp(userId, request.Code);
        return Results.Ok(new { totpEnabled = true });
    }
    catch (UnauthorizedAccessException)
    {
        return Results.Unauthorized();
    }
    catch (InvalidOperationException ex)
    {
        return Results.BadRequest(new { error = ex.Message });
    }
}).RequireAuthorization();

app.MapGet("/api/me", (ClaimsPrincipal principal, AuthService auth) =>
{
    var userId = ResolveUserId(principal);
    if (userId is null)
        return Results.Unauthorized();

    var user = auth.GetProfile(userId);
    return Results.Ok(new
    {
        user.UserId,
        user.Email,
        role = user.Role.ToString(),
        user.TotpEnabled
    });
}).RequireAuthorization();

app.MapGet("/api/admin/ping", () => Results.Ok(new { ok = true, scope = "admin" }))
    .RequireAuthorization("AdminOnly");

app.MapGet("/api/customer/accounts/summary", (ClaimsPrincipal principal) =>
{
    var accounts = new[] { new { accountId = "DEMO-001", currency = "TRY", availableBalance = 1250.00m } };
    return Results.Ok(new { customerId = ResolveUserId(principal), accounts });
}).RequireAuthorization(policy => policy.RequireRole(nameof(UserRole.Customer), nameof(UserRole.Admin)));

app.MapGet("/api/teller/customers/lookup", (string email) =>
{
    if (string.IsNullOrWhiteSpace(email) || !email.Contains('@', StringComparison.Ordinal))
        return Results.BadRequest(new { error = "A valid email is required." });
    return Results.Ok(new { email = email.Trim().ToLowerInvariant(), customerId = "demo-customer", status = "mocked" });
}).RequireAuthorization(policy => policy.RequireRole(nameof(UserRole.Teller), nameof(UserRole.Admin)));

app.MapGet("/health", () => Results.Ok(new { status = "healthy", service = "BankingAuthService" }));

app.Run();

static string? ResolveUserId(ClaimsPrincipal principal) =>
    principal.FindFirstValue(ClaimTypes.NameIdentifier)
    ?? principal.FindFirstValue(JwtRegisteredClaimNames.Sub)
    ?? principal.FindFirstValue("sub");

/// <summary>
/// Rewrites a relative "Data Source=..." path so the sqlite file always resolves against the
/// app's content root, regardless of the process's current working directory. Absolute paths
/// (e.g. the Docker volume mount) and non-file connection strings pass through unchanged.
/// </summary>
static string ResolveSqliteConnectionString(string connectionString, string contentRootPath)
{
    var builder = new Microsoft.Data.Sqlite.SqliteConnectionStringBuilder(connectionString);
    if (!string.IsNullOrWhiteSpace(builder.DataSource) && !Path.IsPathRooted(builder.DataSource))
        builder.DataSource = Path.Combine(contentRootPath, builder.DataSource);
    return builder.ToString();
}

public partial class Program;
