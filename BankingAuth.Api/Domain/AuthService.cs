using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using OtpNet;

namespace BankingAuth.Api.Domain;

public sealed class AuthService
{
    private readonly object _gate = new();
    private readonly Dictionary<string, UserAccount> _usersByEmail = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, RefreshToken> _refreshTokens = new(StringComparer.Ordinal);
    private readonly byte[] _signingKey;

    public AuthService(string jwtSigningKey)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(jwtSigningKey);
        _signingKey = Encoding.UTF8.GetBytes(jwtSigningKey);
    }

    public UserAccount Register(RegisterRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (string.IsNullOrWhiteSpace(request.Email) || string.IsNullOrWhiteSpace(request.Password))
            throw new InvalidOperationException("Email and password are required.");
        if (request.Password.Length < 8)
            throw new InvalidOperationException("Password must be at least 8 characters.");

        if (!Enum.TryParse<UserRole>(request.Role, ignoreCase: true, out var role))
            throw new InvalidOperationException("Role must be Customer or Teller.");
        if (role is UserRole.Admin)
            throw new InvalidOperationException("Admin accounts cannot be self-registered.");

        lock (_gate)
        {
            if (_usersByEmail.ContainsKey(request.Email.Trim()))
                throw new InvalidOperationException("Email already registered.");

            var user = new UserAccount
            {
                UserId = Guid.NewGuid().ToString("N"),
                Email = request.Email.Trim().ToLowerInvariant(),
                PasswordHash = PasswordHasher.Hash(request.Password),
                Role = role
            };
            _usersByEmail[user.Email] = user;
            return user;
        }
    }

    /// <summary>
    /// Creates a bootstrap Admin for demos and tests. Not exposed over the public register API.
    /// </summary>
    public UserAccount EnsureAdmin(string email, string password)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(email);
        ArgumentException.ThrowIfNullOrWhiteSpace(password);
        if (password.Length < 8)
            throw new InvalidOperationException("Password must be at least 8 characters.");

        lock (_gate)
        {
            var key = email.Trim().ToLowerInvariant();
            if (_usersByEmail.TryGetValue(key, out var existing))
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
            _usersByEmail[user.Email] = user;
            return user;
        }
    }

    public TokenResponse Login(LoginRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        lock (_gate)
        {
            if (!_usersByEmail.TryGetValue(request.Email.Trim(), out var user)
                || !PasswordHasher.Verify(request.Password, user.PasswordHash))
            {
                throw new UnauthorizedAccessException("Invalid email or password.");
            }

            if (user.TotpEnabled)
            {
                if (string.IsNullOrWhiteSpace(request.TotpCode) || !VerifyTotpCode(user, request.TotpCode))
                    throw new UnauthorizedAccessException("Valid TOTP code is required.");
            }

            return IssueTokens(user);
        }
    }

    public TokenResponse Refresh(string refreshToken)
    {
        lock (_gate)
        {
            if (!_refreshTokens.TryGetValue(refreshToken, out var stored)
                || stored.Revoked
                || stored.ExpiresAt < DateTimeOffset.UtcNow)
            {
                throw new UnauthorizedAccessException("Invalid refresh token.");
            }

            var user = _usersByEmail.Values.First(u => u.UserId == stored.UserId);
            stored.Revoked = true;
            return IssueTokens(user);
        }
    }

    public EnableTotpResponse BeginEnableTotp(string userId)
    {
        lock (_gate)
        {
            var user = GetUserById(userId);
            var secret = KeyGeneration.GenerateRandomKey(20);
            user.TotpSecret = Base32Encoding.ToString(secret);
            user.TotpEnabled = false;
            var uri = new OtpUri(OtpType.Totp, secret, user.Email, "BankingAuth").ToString();
            return new EnableTotpResponse(user.TotpSecret, uri);
        }
    }

    public void ConfirmEnableTotp(string userId, string code)
    {
        lock (_gate)
        {
            var user = GetUserById(userId);
            if (string.IsNullOrWhiteSpace(user.TotpSecret))
                throw new InvalidOperationException("TOTP setup was not started.");
            if (!VerifyTotpCode(user, code))
                throw new UnauthorizedAccessException("Invalid TOTP code.");
            user.TotpEnabled = true;
        }
    }

    public UserAccount GetProfile(string userId)
    {
        lock (_gate)
        {
            return GetUserById(userId);
        }
    }

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
            issuer: "banking-auth-service",
            audience: "banking-clients",
            claims: claims,
            expires: expires.UtcDateTime,
            signingCredentials: credentials);

        var access = new JwtSecurityTokenHandler().WriteToken(jwt);
        var refresh = Convert.ToBase64String(RandomNumberGenerator.GetBytes(48));
        _refreshTokens[refresh] = new RefreshToken
        {
            Token = refresh,
            UserId = user.UserId,
            ExpiresAt = DateTimeOffset.UtcNow.AddDays(7)
        };

        return new TokenResponse(access, refresh, expires, RequiresTotp: false);
    }

    private UserAccount GetUserById(string userId)
    {
        var user = _usersByEmail.Values.FirstOrDefault(u => u.UserId == userId);
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
}
