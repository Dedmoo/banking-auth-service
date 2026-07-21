using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using BankingAuth.Api.Domain;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

var jwtKey = builder.Configuration["Jwt:SigningKey"];
if (string.IsNullOrWhiteSpace(jwtKey))
    throw new InvalidOperationException("Jwt:SigningKey must be configured in appsettings.");

builder.Services.AddOpenApi();
builder.Services.AddSingleton(new AuthService(jwtKey));
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
            ValidIssuer = "banking-auth-service",
            ValidAudience = "banking-clients",
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey))
        };
    });
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("AdminOnly", policy => policy.RequireRole(nameof(UserRole.Admin)));
});

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

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

app.MapGet("/health", () => Results.Ok(new { status = "healthy", service = "banking-auth-service" }));

app.Run();

static string? ResolveUserId(ClaimsPrincipal principal) =>
    principal.FindFirstValue(ClaimTypes.NameIdentifier)
    ?? principal.FindFirstValue(JwtRegisteredClaimNames.Sub)
    ?? principal.FindFirstValue("sub");

public partial class Program;
