using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.Sqlite;
using SqlIncidentDemo.Middleware;

namespace SqlIncidentDemo.Controllers;

[ApiController]
[Route("api/[controller]")]
public class UsersController : ControllerBase
{
    private readonly string _connectionString;

    public UsersController(IConfiguration configuration)
    {
        _connectionString = configuration.GetConnectionString("Users")!;
    }

    // INTENTIONALLY VULNERABLE: user input is concatenated straight into the SQL,
    // so an attacker can change the query itself. Only the detection middleware
    // stands in front of it.
    [HttpGet("SearchVulnerable")]
    public IActionResult SearchVulnerable([FromQuery] string username)
    {
        using var connection = new SqliteConnection(_connectionString);
        connection.Open();

        using var command = connection.CreateCommand();
        command.CommandText =
            "SELECT Id, Username, Email, Role FROM Users WHERE Username = '" + username + "'";

        return Ok(ReadUsers(command));
    }

    // SECURE BY DESIGN: a parameterized query. The input is always treated as a
    // value, never as SQL, so injection is impossible here even without the
    // middleware. That is why this endpoint opts out of it: the demo can show
    // the payload being harmlessly treated as a literal username.
    [HttpGet("SearchSecure")]
    [SkipSqlInjectionDetection]
    public IActionResult SearchSecure([FromQuery] string username)
    {
        using var connection = new SqliteConnection(_connectionString);
        connection.Open();

        using var command = connection.CreateCommand();
        command.CommandText = "SELECT Id, Username, Email, Role FROM Users WHERE Username = @username";
        command.Parameters.AddWithValue("@username", username);

        return Ok(ReadUsers(command));
    }

    private static List<UserDto> ReadUsers(SqliteCommand command)
    {
        var users = new List<UserDto>();
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            users.Add(new UserDto(reader.GetInt32(0), reader.GetString(1), reader.GetString(2), reader.GetString(3)));
        }
        return users;
    }
}

public record UserDto(int Id, string Username, string Email, string Role);
