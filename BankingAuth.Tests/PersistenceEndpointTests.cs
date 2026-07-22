using System.Net;
using System.Net.Http.Json;

namespace BankingAuth.Tests;

/// <summary>
/// Proves persistence end-to-end over HTTP: a user registered against one running instance of
/// the API can still log in after that instance is disposed (simulating a restart) and a brand
/// new <see cref="AuthWebApplicationFactory"/> is started against the same SQLite file.
/// </summary>
public sealed class PersistenceEndpointTests
{
    [Fact]
    public async Task RegisteredUser_SurvivesApiRestart_AndCanLoginAfterwards()
    {
        var dbPath = TestDbContextFactory.CreateTempDbPath();
        try
        {
            using (var firstRun = new AuthWebApplicationFactory(dbPath, ownsDbFile: false))
            {
                var client = firstRun.CreateClient();
                var register = await client.PostAsJsonAsync("/api/auth/register", new
                {
                    email = "restart@bank.test",
                    password = "Secret123!",
                    role = "Customer"
                });
                var registerBody = await register.Content.ReadAsStringAsync();
                Assert.True(register.StatusCode == HttpStatusCode.Created, $"{register.StatusCode}: {registerBody}");
            }

            using var secondRun = new AuthWebApplicationFactory(dbPath, ownsDbFile: false);
            var secondClient = secondRun.CreateClient();
            var login = await secondClient.PostAsJsonAsync("/api/auth/login", new
            {
                email = "restart@bank.test",
                password = "Secret123!"
            });

            Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        }
        finally
        {
            TestDbContextFactory.DeleteDbFile(dbPath);
        }
    }
}
