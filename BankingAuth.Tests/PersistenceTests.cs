using BankingAuth.Api.Domain;

namespace BankingAuth.Tests;

/// <summary>
/// Proves that user and refresh-token data survives across separate <see cref="AuthDbContext"/>
/// instances backed by the same SQLite file, i.e. real persistence rather than in-memory state.
/// </summary>
public sealed class PersistenceTests : IDisposable
{
    private const string SigningKey = "persistence-test-signing-key-32-chars-min!";
    private readonly string _dbPath = TestDbContextFactory.CreateTempDbPath();

    [Fact]
    public void RegisteredUser_SurvivesNewDbContextScope_AndCanLogin()
    {
        using (var firstScopeDb = TestDbContextFactory.OpenFileBased(_dbPath))
        {
            var authInFirstScope = new AuthService(firstScopeDb, SigningKey);
            authInFirstScope.Register(new RegisterRequest("persist@bank.test", "Secret123!", "Customer"));
        }

        using var secondScopeDb = TestDbContextFactory.OpenFileBased(_dbPath);
        var authInSecondScope = new AuthService(secondScopeDb, SigningKey);
        var tokens = authInSecondScope.Login(new LoginRequest("persist@bank.test", "Secret123!"));

        Assert.False(string.IsNullOrWhiteSpace(tokens.AccessToken));
    }

    [Fact]
    public void RefreshToken_IssuedInOneScope_RotatesInAnotherScope()
    {
        TokenResponse first;
        using (var firstScopeDb = TestDbContextFactory.OpenFileBased(_dbPath))
        {
            var authInFirstScope = new AuthService(firstScopeDb, SigningKey);
            authInFirstScope.Register(new RegisterRequest("rotate@bank.test", "Secret123!", "Customer"));
            first = authInFirstScope.Login(new LoginRequest("rotate@bank.test", "Secret123!"));
        }

        using var secondScopeDb = TestDbContextFactory.OpenFileBased(_dbPath);
        var authInSecondScope = new AuthService(secondScopeDb, SigningKey);
        var second = authInSecondScope.Refresh(first.RefreshToken);

        Assert.NotEqual(first.RefreshToken, second.RefreshToken);
        Assert.Throws<UnauthorizedAccessException>(() => authInSecondScope.Refresh(first.RefreshToken));
    }

    [Fact]
    public void FailedLoginLockout_PersistsAcrossScopes()
    {
        using (var firstScopeDb = TestDbContextFactory.OpenFileBased(_dbPath))
        {
            var authInFirstScope = new AuthService(firstScopeDb, SigningKey);
            authInFirstScope.Register(new RegisterRequest("lockout-persist@bank.test", "Secret123!", "Customer"));
            for (var attempt = 0; attempt < 5; attempt++)
                Assert.Throws<UnauthorizedAccessException>(() =>
                    authInFirstScope.Login(new LoginRequest("lockout-persist@bank.test", "wrong123")));
        }

        using var secondScopeDb = TestDbContextFactory.OpenFileBased(_dbPath);
        var authInSecondScope = new AuthService(secondScopeDb, SigningKey);
        Assert.Throws<UnauthorizedAccessException>(() =>
            authInSecondScope.Login(new LoginRequest("lockout-persist@bank.test", "Secret123!")));
    }

    public void Dispose() => TestDbContextFactory.DeleteDbFile(_dbPath);
}
