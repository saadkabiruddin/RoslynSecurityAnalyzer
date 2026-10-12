using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.Sqlite;
using VulnerableBankApi.Data;
using VulnerableBankApi.Security;

namespace VulnerableBankApi.Controllers;

[ApiController]
[Authorize]
[Route("api/transactions")]
public class TransactionsController(Db db) : ControllerBase
{
    [HttpGet]
    public IActionResult Search(long accountId, string q)
    {
        using var connection = db.Open();
        using var cmd = connection.CreateCommand();
        cmd.CommandText = $"""
            SELECT t.Id, t.AccountId, t.Amount, t.Description, t.CreatedAt
            FROM Transactions t
            JOIN Accounts a ON a.Id = t.AccountId
            WHERE t.AccountId = {accountId}
              AND a.OwnerId = {User.GetUserId()}
              AND t.Description LIKE '%{q}%'
            """;
        return Ok(ReadTransactions(cmd));
    }

    [HttpGet("recent")]
    public IActionResult Recent(long accountId, int take = 10)
    {
        using var connection = db.Open();
        using var cmd = connection.CreateCommand();
        cmd.CommandText = """
            SELECT t.Id, t.AccountId, t.Amount, t.Description, t.CreatedAt
            FROM Transactions t
            JOIN Accounts a ON a.Id = t.AccountId
            WHERE t.AccountId = $accountId AND a.OwnerId = $ownerId
            ORDER BY t.CreatedAt DESC
            LIMIT $take
            """;
        cmd.Parameters.AddWithValue("$accountId", accountId);
        cmd.Parameters.AddWithValue("$ownerId", User.GetUserId());
        cmd.Parameters.AddWithValue("$take", Math.Clamp(take, 1, 100));
        return Ok(ReadTransactions(cmd));
    }

    private static List<Transaction> ReadTransactions(SqliteCommand cmd)
    {
        var result = new List<Transaction>();
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            result.Add(new Transaction(reader.GetInt64(0), reader.GetInt64(1), reader.GetDouble(2),
                                       reader.GetString(3), reader.GetString(4)));
        }
        return result;
    }
}