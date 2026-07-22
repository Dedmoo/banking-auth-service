using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;

namespace BankingAuth.Tests;

/// <summary>
/// A <see cref="WebApplicationFactory{TEntryPoint}"/> that points the API at its own temp-file
/// SQLite database, so integration test classes never share persisted state with each other or
/// with a developer's local `dotnet run` database. Pass an explicit <paramref name="dbPath"/> to
/// simulate an API restart against the same database (see PersistenceEndpointTests). The
/// parameterless constructor is required by xUnit's <c>IClassFixture</c> activation.
/// </summary>
public sealed class AuthWebApplicationFactory : WebApplicationFactory<Program>
{
    private readonly bool _ownsDbFile;

    public AuthWebApplicationFactory() : this(dbPath: null, ownsDbFile: true)
    {
    }

    // Internal (not public) so xUnit's IClassFixture activation - which requires exactly one
    // public constructor - still resolves the parameterless constructor above.
    internal AuthWebApplicationFactory(string? dbPath, bool ownsDbFile)
    {
        DbPath = dbPath ?? TestDbContextFactory.CreateTempDbPath();
        _ownsDbFile = ownsDbFile;
    }

    public string DbPath { get; }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Development");
        builder.ConfigureAppConfiguration((_, configBuilder) =>
        {
            configBuilder.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ConnectionStrings:BankingAuthDb"] = $"Data Source={DbPath}"
            });
        });
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        if (disposing && _ownsDbFile)
            TestDbContextFactory.DeleteDbFile(DbPath);
    }
}
