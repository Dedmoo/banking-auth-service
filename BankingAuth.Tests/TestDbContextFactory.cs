using BankingAuth.Api.Data;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

namespace BankingAuth.Tests;

/// <summary>
/// Builds isolated SQLite-backed <see cref="AuthDbContext"/> instances for tests, keeping every
/// test's data separate so tests can run in parallel without sharing state.
/// </summary>
public static class TestDbContextFactory
{
    /// <summary>
    /// A private, connection-scoped in-memory SQLite database. Fast and fully isolated: the data
    /// disappears once the returned context (and its underlying connection) is disposed.
    /// </summary>
    public static AuthDbContext CreateInMemorySqlite()
    {
        var connection = new SqliteConnection("Data Source=:memory:");
        connection.Open();
        var options = new DbContextOptionsBuilder<AuthDbContext>()
            .UseSqlite(connection)
            .Options;
        var context = new AuthDbContext(options);
        context.Database.EnsureCreated();
        return context;
    }

    /// <summary>
    /// A unique temp-file SQLite database path, used to prove data survives across separate
    /// <see cref="AuthDbContext"/> instances (i.e. real persistence, not just an open connection).
    /// </summary>
    public static string CreateTempDbPath() =>
        Path.Combine(Path.GetTempPath(), $"bankingauth-tests-{Guid.NewGuid():N}.db");

    public static AuthDbContext OpenFileBased(string dbPath)
    {
        var options = new DbContextOptionsBuilder<AuthDbContext>()
            .UseSqlite($"Data Source={dbPath}")
            .Options;
        var context = new AuthDbContext(options);
        context.Database.EnsureCreated();
        return context;
    }

    public static void DeleteDbFile(string dbPath)
    {
        SqliteConnection.ClearAllPools();
        foreach (var path in new[] { dbPath, $"{dbPath}-wal", $"{dbPath}-shm", $"{dbPath}-journal" })
        {
            if (File.Exists(path))
                File.Delete(path);
        }
    }
}
