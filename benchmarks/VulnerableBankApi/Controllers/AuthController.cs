using Microsoft.AspNetCore.Mvc;
using VulnerableBankApi.Data;
using VulnerableBankApi.Security;

namespace VulnerableBankApi.Controllers;

[ApiController]
[Route("api/auth")]
public class AuthController(Db db, ILogger<AuthController> logger) : ControllerBase
{
    public record LoginRequest(string Username, string Password);

    [HttpPost("login")]
    public IActionResult Login(LoginRequest request)
    {
        logger.LogInformation("Login attempt for {Username} with password {Password}",
            request.Username, request.Password);

        using var connection = db.Open();
        using var cmd = connection.CreateCommand();
        cmd.CommandText = "SELECT Id, Role, PasswordHash FROM Users WHERE Username = $username";
        cmd.Parameters.AddWithValue("$username", request.Username);

        using var reader = cmd.ExecuteReader();
        if (!reader.Read() || reader.GetString(2) != PasswordHasher.Hash(request.Password))
            return Unauthorized();

        var token = TokenService.Create(reader.GetInt64(0), reader.GetString(1));
        return Ok(new { token });
    }

    [HttpGet("logout")]
    public IActionResult Logout(string returnUrl)
    {
        return Redirect(returnUrl);
    }
}