using Microsoft.Data.Sqlite;
using Serilog;
using SqlIncidentDemo.Middleware;

// Structured security logging to the console and a daily rolling file.
Log.Logger = new LoggerConfiguration()
    .WriteTo.Console()
    .WriteTo.File("security_incidents.log", rollingInterval: RollingInterval.Day)
    .CreateLogger();

var builder = WebApplication.CreateBuilder(args);
builder.Host.UseSerilog();
builder.Services.AddControllers();

// A shared in-memory SQLite database is deleted as soon as its last connection
// closes. This connection stays open for the app's lifetime to keep the
// database alive; the DI container disposes it on shutdown.
var connectionString = builder.Configuration.GetConnectionString("Users")
    ?? throw new InvalidOperationException("Connection string 'Users' is missing.");
var keepAliveConnection = new SqliteConnection(connectionString);
keepAliveConnection.Open();
SeedDatabase(keepAliveConnection);
builder.Services.AddSingleton(keepAliveConnection);

var app = builder.Build();

app.UseRouting();

// Incident response: detection (phase 2) and containment (phase 3).
// It runs after routing so it can see which endpoint a request targets.
app.UseMiddleware<SqlInjectionDetectionMiddleware>();

app.MapControllers();
app.Run();

static void SeedDatabase(SqliteConnection connection)
{
    using var command = connection.CreateCommand();
    command.CommandText = """
        CREATE TABLE Users (
            Id INTEGER PRIMARY KEY AUTOINCREMENT,
            Username TEXT NOT NULL,
            Email TEXT NOT NULL,
            Role TEXT NOT NULL
        );
        INSERT INTO Users (Username, Email, Role) VALUES ('admin', 'admin@example.com', 'Administrator');
        INSERT INTO Users (Username, Email, Role) VALUES ('alice', 'alice@example.com', 'User');
        INSERT INTO Users (Username, Email, Role) VALUES ('bob', 'bob@example.com', 'User');
        """;
    command.ExecuteNonQuery();
}
