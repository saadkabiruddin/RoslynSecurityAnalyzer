using Microsoft.Data.Sqlite;
using VulnerableBankApi.Security;

namespace VulnerableBankApi.Data;

public class Db
{
    public SqliteConnection Open()
    {
        var connection = new SqliteConnection("Data Source=bank.db");
        connection.Open();
        return connection;
    }

    public void Initialize()
    {
        using var connection = Open();
        using var cmd = connection.CreateCommand();
        cmd.CommandText = """
            CREATE TABLE IF NOT EXISTS Users (
                Id INTEGER PRIMARY KEY, Username TEXT NOT NULL UNIQUE,
                PasswordHash TEXT NOT NULL, Role TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS Accounts (
                Id INTEGER PRIMARY KEY, OwnerId INTEGER NOT NULL,
                AccountNo TEXT NOT NULL, Balance REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS Transactions (
                Id INTEGER PRIMARY KEY, AccountId INTEGER NOT NULL, Amount REAL NOT NULL,
                Description TEXT NOT NULL, CreatedAt TEXT NOT NULL);
            INSERT OR IGNORE INTO Users VALUES
                (1, 'alice', $alice, 'Customer'),
                (2, 'bob',   $bob,   'Customer'),
                (3, 'admin', $admin, 'Admin');
            INSERT OR IGNORE INTO Accounts VALUES
                (1, 1, '1001-0001', 52000), (2, 2, '1001-0002', 8700), (3, 3, '1001-0003', 0);
            INSERT OR IGNORE INTO Transactions VALUES
                (1, 1, -1500, 'Electricity bill', '2026-09-01'),
                (2, 1, 30000, 'Salary', '2026-09-05'),
                (3, 2, -200, 'Mobile recharge', '2026-09-07');
            """;
        cmd.Parameters.AddWithValue("$alice", PasswordHasher.Hash("alice123"));
        cmd.Parameters.AddWithValue("$bob", PasswordHasher.Hash("bob123"));
        cmd.Parameters.AddWithValue("$admin", PasswordHasher.Hash("admin123"));
        cmd.ExecuteNonQuery();
    }
}