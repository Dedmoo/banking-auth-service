using BankingAuth.Api.Domain;
using OtpNet;

namespace BankingAuth.Tests;

public class AuthServiceTests
{
    private static AuthService Create() =>
        new("unit-test-signing-key-must-be-long-enough!");

    [Fact]
    public void RegisterAndLogin_IssuesTokens()
    {
        var auth = Create();
        auth.Register(new RegisterRequest("alice@bank.test", "Secret123!", "Customer"));
        var tokens = auth.Login(new LoginRequest("alice@bank.test", "Secret123!"));

        Assert.False(string.IsNullOrWhiteSpace(tokens.AccessToken));
        Assert.False(string.IsNullOrWhiteSpace(tokens.RefreshToken));
    }

    [Fact]
    public void Login_WrongPassword_Throws()
    {
        var auth = Create();
        auth.Register(new RegisterRequest("bob@bank.test", "Secret123!", "Teller"));
        Assert.Throws<UnauthorizedAccessException>(() =>
            auth.Login(new LoginRequest("bob@bank.test", "wrong-pass")));
    }

    [Fact]
    public void Refresh_RotatesRefreshToken()
    {
        var auth = Create();
        auth.EnsureAdmin("carol@bank.test", "Secret123!");
        var first = auth.Login(new LoginRequest("carol@bank.test", "Secret123!"));
        var second = auth.Refresh(first.RefreshToken);

        Assert.NotEqual(first.RefreshToken, second.RefreshToken);
        Assert.Throws<UnauthorizedAccessException>(() => auth.Refresh(first.RefreshToken));
    }

    [Fact]
    public void Register_RejectsSelfServiceAdmin()
    {
        var auth = Create();
        var ex = Assert.Throws<InvalidOperationException>(() =>
            auth.Register(new RegisterRequest("eve@bank.test", "Secret123!", "Admin")));
        Assert.Contains("Admin", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Totp_EnableAndLogin_RequiresCode()
    {
        var auth = Create();
        var user = auth.Register(new RegisterRequest("dave@bank.test", "Secret123!", "Customer"));
        var setup = auth.BeginEnableTotp(user.UserId);
        var code = new Totp(Base32Encoding.ToBytes(setup.SharedSecret)).ComputeTotp();
        auth.ConfirmEnableTotp(user.UserId, code);

        Assert.Throws<UnauthorizedAccessException>(() =>
            auth.Login(new LoginRequest("dave@bank.test", "Secret123!", "000000")));

        var challenge = auth.Login(new LoginRequest("dave@bank.test", "Secret123!"));
        Assert.True(challenge.RequiresTotp);
        Assert.True(string.IsNullOrEmpty(challenge.AccessToken));

        var loginCode = new Totp(Base32Encoding.ToBytes(setup.SharedSecret)).ComputeTotp();
        var tokens = auth.Login(new LoginRequest("dave@bank.test", "Secret123!", loginCode));
        Assert.False(string.IsNullOrWhiteSpace(tokens.AccessToken));
    }

    [Fact]
    public void PasswordHasher_RoundTrip()
    {
        var hash = PasswordHasher.Hash("HelloBank1");
        Assert.True(PasswordHasher.Verify("HelloBank1", hash));
        Assert.False(PasswordHasher.Verify("HelloBank2", hash));
    }
}
