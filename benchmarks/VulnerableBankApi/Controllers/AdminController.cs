using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using VulnerableBankApi.Data;

namespace VulnerableBankApi.Controllers;

[ApiController]
[Route("api/admin")]
public class AdminController(Db db) : ControllerBase
{
    public record BalanceAdjustment(double Amount, string Reason);

    [Authorize(Roles = "Admin")]
    [HttpGet("users")]
    public IActionResult ListUsers()
    {
        using var connection = db.Open();
        using var cmd = connection.CreateCommand();
        cmd.CommandText = "SELECT Id, Username, Role FROM Users";

        var users = new List<UserSummary>();
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            users.Add(new UserSummary(reader.GetInt64(0), reader.GetString(1), reader.GetString(2)));
        }
        return Ok(users);
    }

    [HttpPost("accounts/{id:long}/adjust-balance")]
    public IActionResult AdjustBalance(long id, BalanceAdjustment adjustment)
    {
        using var connection = db.Open();
        using var cmd = connection.CreateCommand();
        cmd.CommandText = "UPDATE Accounts SET Balance = Balance + $amount WHERE Id = $id";
        cmd.Parameters.AddWithValue("$amount", adjustment.Amount);
        cmd.Parameters.AddWithValue("$id", id);

        return cmd.ExecuteNonQuery() == 0 ? NotFound() : NoContent();
    }
}