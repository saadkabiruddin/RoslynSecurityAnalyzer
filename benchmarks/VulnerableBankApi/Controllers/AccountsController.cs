using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.Sqlite;
using VulnerableBankApi.Data;
using VulnerableBankApi.Security;

namespace VulnerableBankApi.Controllers;

[ApiController]
[Authorize]
[Route("api/accounts")]
public class AccountsController(Db db) : ControllerBase
{
    [HttpGet("mine")]
    public IActionResult GetMine()
    {
        using var connection = db.Open();
        using var cmd = connection.CreateCommand();
        cmd.CommandText = "SELECT Id, OwnerId, AccountNo, Balance FROM Accounts WHERE OwnerId = $ownerId";
        cmd.Parameters.AddWithValue("$ownerId", User.GetUserId());
        return Ok(ReadAccounts(cmd));
    }

    [HttpGet("{id:long}")]
    public IActionResult GetById(long id)
    {
        using var connection = db.Open();
        using var cmd = connection.CreateCommand();
        cmd.CommandText = "SELECT Id, OwnerId, AccountNo, Balance FROM Accounts WHERE Id = $id";
        cmd.Parameters.AddWithValue("$id", id);

        var account = ReadAccounts(cmd).FirstOrDefault();
        return account is null ? NotFound() : Ok(account);
    }

    [HttpGet("search")]
    public IActionResult Search(string accountNo)
    {
        using var connection = db.Open();
        var sql = "SELECT Id, OwnerId, AccountNo, Balance FROM Accounts WHERE AccountNo = '"
                  + accountNo + "' AND OwnerId = " + User.GetUserId();
        using var cmd = new SqliteCommand(sql, connection);
        return Ok(ReadAccounts(cmd));
    }

    private static List<Account> ReadAccounts(SqliteCommand cmd)
    {
        var result = new List<Account>();
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            result.Add(new Account(reader.GetInt64(0), reader.GetInt64(1),
                                   reader.GetString(2), reader.GetDouble(3)));
        }
        return result;
    }
}