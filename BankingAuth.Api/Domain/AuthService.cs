using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using BankingAuth.Api.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using OtpNet;

namespace BankingAuth.Api.Domain;

public sealed class AuthService
{
    private const int MaximumFailedLoginAttempts = 5;
    private static readonly TimeSpan LockoutDuration = TimeSpan.FromMinutes(15);
    private readonly AuthDbContext _db;
    private readonly byte[] _signingKey;

    public AuthService(AuthDbContext db, string jwtSigningKey)
    {
        ArgumentNullException.ThrowIfNull(db);
        ArgumentException.ThrowIfNullOrWhiteSpace(jwtSigningKey);
        _db = db;
        _signingKey = Encoding.UTF8.GetBytes(jwtSigningKey);
    }

    public UserAccount Register(RegisterRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (string.IsNullOrWhiteSpace(request.Email) || string.IsNullOrWhiteSpace(request.Password))
            throw new InvalidOperationException("Email and password are required.");
        ValidatePassword(request.Password);

        if (!Enum.TryParse<UserRole>(request.Role, ignoreCase: true, out var role))
            throw new InvalidOperationException("Role must be Customer or Teller.");
        if (role is UserRole.Admin)
            throw new InvalidOperationException("Admin accounts cannot be self-registered.");

        var email = NormalizeEmail(request.Email);
        if (_db.Users.Any(u => u.Email == email))
            throw new InvalidOperationException("Email already registered.");

        var user = new UserAccount
        {
            UserId = Guid.NewGuid().ToString("N"),
            Email = email,
            PasswordHash = PasswordHasher.Hash(request.Password),
            Role = role
        };

        _db.Users.Add(user);
        try
        {
            _db.SaveChanges();
        }
        catch (DbUpdateException)
        {
            // Unique index on Email is the race-condition backstop behind the pre-check above.
            throw new InvalidOperationException("Email already registered.");
        }
        return user;
    }

    /// <summary>
    /// Creates a bootstrap Admin for demos and tests. Not exposed over the public register API.
    /// </summary>
    public UserAccount EnsureAdmin(string email, string password)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(email);
        ArgumentException.ThrowIfNullOrWhiteSpace(password);
        ValidatePassword(password);

        var key = NormalizeEmail(email);
        var existing = _db.Users.FirstOrDefault(u => u.Email == key);
        if (existing is not null)
        {
            if (existing.Role != UserRole.Admin)
                throw new InvalidOperationException("Email is already registered as a non-admin user.");
            return existing;
        }

        var user = new UserAccount
        {
            UserId = Guid.NewGuid().ToString("N"),
            Email = key,
            PasswordHash = PasswordHasher.Hash(password),
            Role = UserRole.Admin
        };
        _db.Users.Add(user);
        _db.SaveChanges();
        return user;
    }

    public TokenResponse Login(LoginRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        var email = NormalizeEmail(request.Email);
        var user = _db.Users.FirstOrDefault(u => u.Email == email);
        if (user is null)
            throw new UnauthorizedAccessException("Invalid email or password.");
        if (user.LockedUntil is { } lockedUntil && lockedUntil > DateTimeOffset.UtcNow)
            throw new UnauthorizedAccessException("Account is temporarily locked.");
        if (!PasswordHasher.Verify(request.Password, user.PasswordHash))
        {
            user.FailedLoginAttempts++;
            if (user.FailedLoginAttempts >= MaximumFailedLoginAttempts)
            {
                user.FailedLoginAttempts = 0;
                user.LockedUntil = DateTimeOffset.UtcNow.Add(LockoutDuration);
            }
            _db.SaveChanges();
            throw new UnauthorizedAccessException("Invalid email or password.");
        }
        user.FailedLoginAttempts = 0;
        user.LockedUntil = null;

        if (user.TotpEnabled)
        {
            if (string.IsNullOrWhiteSpace(request.TotpCode))
            {
                _db.SaveChanges();
                return new TokenResponse("", "", DateTimeOffset.UtcNow, RequiresTotp: true);
            }
            if (!VerifyTotpCode(user, request.TotpCode))
            {
                _db.SaveChanges();
                throw new UnauthorizedAccessException("Valid TOTP code is required.");
            }
        }

        return IssueTokens(user);
    }

    public TokenResponse Refresh(string refreshToken)
    {
        using var transaction = _db.Database.BeginTransaction();

        var stored = _db.RefreshTokens.FirstOrDefault(t => t.Token == refreshToken);
        if (stored is null || stored.Revoked || stored.ExpiresAt < DateTimeOffset.UtcNow)
            throw new UnauthorizedAccessException("Invalid refresh token.");

        var user = _db.Users.FirstOrDefault(u => u.UserId == stored.UserId)
            ?? throw new UnauthorizedAccessException("Invalid refresh token.");
        stored.Revoked = true;
        _db.SaveChanges();

        var response = IssueTokens(user);
        transaction.Commit();
        return response;
    }

    public void Logout(string refreshToken)
    {
        if (string.IsNullOrWhiteSpace(refreshToken))
            throw new UnauthorizedAccessException("Refresh token is required.");
        var stored = _db.RefreshTokens.FirstOrDefault(t => t.Token == refreshToken);
        if (stored is null || stored.Revoked)
            throw new UnauthorizedAccessException("Invalid refresh token.");
        stored.Revoked = true;
        _db.SaveChanges();
    }

    public EnableTotpResponse BeginEnableTotp(string userId)
    {
        var user = GetUserById(userId);
        var secret = KeyGeneration.GenerateRandomKey(20);
        user.TotpSecret = Base32Encoding.ToString(secret);
        user.TotpEnabled = false;
        _db.SaveChanges();
        var uri = new OtpUri(OtpType.Totp, secret, user.Email, "BankingAuth").ToString();
        return new EnableTotpResponse(user.TotpSecret, uri);
    }

    public void ConfirmEnableTotp(string userId, string code)
    {
        var user = GetUserById(userId);
        if (string.IsNullOrWhiteSpace(user.TotpSecret))
            throw new InvalidOperationException("TOTP setup was not started.");
        if (!VerifyTotpCode(user, code))
            throw new UnauthorizedAccessException("Invalid TOTP code.");
        user.TotpEnabled = true;
        _db.SaveChanges();
    }

    public UserAccount GetProfile(string userId) => GetUserById(userId);

    private TokenResponse IssueTokens(UserAccount user)
    {
        var expires = DateTimeOffset.UtcNow.AddMinutes(30);
        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, user.UserId),
            new(JwtRegisteredClaimNames.Email, user.Email),
            new(ClaimTypes.Role, user.Role.ToString())
        };

        var credentials = new SigningCredentials(
            new SymmetricSecurityKey(_signingKey),
            SecurityAlgorithms.HmacSha256);

        var jwt = new JwtSecurityToken(
            issuer: "BankingAuthService",
            audience: "banking-clients",
            claims: claims,
            expires: expires.UtcDateTime,
            signingCredentials: credentials);

        var access = new JwtSecurityTokenHandler().WriteToken(jwt);
        var refresh = Convert.ToBase64String(RandomNumberGenerator.GetBytes(48));
        _db.RefreshTokens.Add(new RefreshToken
        {
            Token = refresh,
            UserId = user.UserId,
            ExpiresAt = DateTimeOffset.UtcNow.AddDays(7)
        });
        _db.SaveChanges();

        return new TokenResponse(access, refresh, expires, RequiresTotp: false);
    }

    private UserAccount GetUserById(string userId)
    {
        var user = _db.Users.FirstOrDefault(u => u.UserId == userId);
        if (user is null)
            throw new KeyNotFoundException("User not found.");
        return user;
    }

    private static bool VerifyTotpCode(UserAccount user, string code)
    {
        if (string.IsNullOrWhiteSpace(user.TotpSecret))
            return false;
        var totp = new Totp(Base32Encoding.ToBytes(user.TotpSecret));
        return totp.VerifyTotp(code.Trim(), out _, new VerificationWindow(1, 1));
    }

    private static void ValidatePassword(string password)
    {
        if (password.Length < 8 || !password.Any(char.IsLetter) || !password.Any(char.IsDigit))
            throw new InvalidOperationException("Password must be at least 8 characters and contain a letter and a digit.");
    }

    private static string NormalizeEmail(string email) => email.Trim().ToLowerInvariant();
}
