namespace BankingAuth.Api.Domain;

public enum UserRole
{
    Customer = 0,
    Teller = 1,
    Admin = 2
}

public sealed class UserAccount
{
    public required string UserId { get; init; }
    public required string Email { get; init; }
    public required string PasswordHash { get; set; }
    public required UserRole Role { get; init; }
    public string? TotpSecret { get; set; }
    public bool TotpEnabled { get; set; }
    public int FailedLoginAttempts { get; set; }
    public DateTimeOffset? LockedUntil { get; set; }
    public DateTimeOffset CreatedAt { get; init; } = DateTimeOffset.UtcNow;
}

public sealed class RefreshToken
{
    public required string Token { get; init; }
    public required string UserId { get; init; }
    public required DateTimeOffset ExpiresAt { get; init; }
    public bool Revoked { get; set; }
}

public sealed record RegisterRequest(string Email, string Password, string Role = "Customer");
public sealed record LoginRequest(string Email, string Password, string? TotpCode = null);
public sealed record TokenResponse(string AccessToken, string RefreshToken, DateTimeOffset ExpiresAt, bool RequiresTotp);
public sealed record RefreshRequest(string RefreshToken);
public sealed record LogoutRequest(string RefreshToken);
public sealed record EnableTotpResponse(string SharedSecret, string OtpAuthUri);
public sealed record VerifyTotpRequest(string Code);
