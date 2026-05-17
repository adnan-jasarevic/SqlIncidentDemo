using SqlIncidentDemo.Middleware;
using Microsoft.Data.Sqlite;
using Serilog;

var builder = WebApplication.CreateBuilder(args);

// Podešavanje Serilog-a za strukturirano logiranje
Log.Logger = new LoggerConfiguration()
    .WriteTo.Console()
    .WriteTo.File("security_incidents.log", rollingInterval: RollingInterval.Day)
    .CreateLogger();
builder.Host.UseSerilog();

builder.Services.AddControllers();

var app = builder.Build();

// 1. Inicijalizacija SQLite baze u memoriji
InitializeDatabase();

// 2. Dodavanje incident response Middleware (Faza detekcije i izolacije)
app.UseMiddleware<SqlInjectionDetectionMiddleware>();

app.MapControllers();
app.Run();

void InitializeDatabase()
{
    // Mode=Memory;Cache=Shared osigurava da baza traje dok je aplikacija upaljena
    using var connection = new SqliteConnection("Data Source=InMemorySample;Mode=Memory;Cache=Shared");
    connection.Open();
    var command = connection.CreateCommand();
    command.CommandText = @"
        CREATE TABLE Users (
            Id INTEGER PRIMARY KEY AUTOINCREMENT,
            Username TEXT,
            Email TEXT,
            Role TEXT
        );
        INSERT INTO Users (Username, Email, Role) VALUES ('admin', 'admin@firma.ba', 'Administrator');
        INSERT INTO Users (Username, Email, Role) VALUES ('adnan', 'adnan@firma.ba', 'Korisnik');
        INSERT INTO Users (Username, Email, Role) VALUES ('test', 'test@firma.ba', 'Korisnik');
    ";
    command.ExecuteNonQuery();
}