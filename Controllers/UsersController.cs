using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.Sqlite;

namespace SqlIncidentDemo.Controllers;

[ApiController]
[Route("api/[controller]")]
public class UsersController : ControllerBase
{
    private readonly string _connectionString = "Data Source=InMemorySample;Mode=Memory;Cache=Shared";

    // RANJIVA METODA
    [HttpGet("SearchVulnerable")]
    public IActionResult SearchVulnerable([FromQuery] string username)
    {
        var users = new List<object>();
        using var connection = new SqliteConnection(_connectionString);
        connection.Open();

        // Primjer lose prakse; Haker može manipulisati SQL sintaksom
        string query = "SELECT Id, Username, Email, Role FROM Users WHERE Username = '" + username + "'";
        
        using var command = new SqliteCommand(query, connection);
        using var reader = command.ExecuteReader();
        
        while (reader.Read())
        {
            users.Add(new { Id = reader.GetInt32(0), Username = reader.GetString(1), Email = reader.GetString(2), Role = reader.GetString(3) });
        }
        return Ok(users);
    }

    // Secure by design metoda
    [HttpGet("SearchSecure")]
    public IActionResult SearchSecure([FromQuery] string username)
    {
        var users = new List<object>();
        using var connection = new SqliteConnection(_connectionString);
        connection.Open();

        // SQL injection ne radi, parametarizovani upiti
        string query = "SELECT Id, Username, Email, Role FROM Users WHERE Username = @username";
        
        using var command = new SqliteCommand(query, connection);
        command.Parameters.AddWithValue("@username", username); // Parametrizacija
        using var reader = command.ExecuteReader();
        
        while (reader.Read())
        {
            users.Add(new { Id = reader.GetInt32(0), Username = reader.GetString(1), Email = reader.GetString(2), Role = reader.GetString(3) });
        }
        return Ok(users);
    }
}