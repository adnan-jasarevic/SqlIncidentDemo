namespace SqlIncidentDemo.Middleware;
using Serilog;

public class SqlInjectionDetectionMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<SqlInjectionDetectionMiddleware> _logger;

    private readonly string[] _sqlSignatures = { "OR '1'='1", "DROP TABLE", "--", ";", "UNION SELECT" };

    public SqlInjectionDetectionMiddleware(RequestDelegate next, ILogger<SqlInjectionDetectionMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var queryString = context.Request.QueryString.ToString();
        
        if (!string.IsNullOrEmpty(queryString))
        {
            // Dekodiramo URL
            string decodedQuery = Uri.UnescapeDataString(queryString).ToUpper();
            
            foreach (var signature in _sqlSignatures)
            {
                if (decodedQuery.Contains(signature.ToUpper()))
                {
                    string clientIp = context.Connection.RemoteIpAddress?.ToString() ?? "Unknown_IP";
                    
                    // FAZA 2: Detekcija i strukturirano logiranje incidenta
                    _logger.LogCritical("INCIDENT DETECTED: SQL Injection pokušaj sa IP {ClientIp}. Payload: {Payload}. Signature matched: {Signature}", 
                        clientIp, decodedQuery, signature);

                    // FAZA 3: Izolacija (Blokiranje zahtjeva prije nego što stigne do ranjivog koda)
                    context.Response.StatusCode = 403;
                    await context.Response.WriteAsync("SECURITY ALERT: Maliciozni SQL obrazac detektovan. Zahtjev je blokiran i CSIRT tim je obavijesten.");
                    return;
                }
            }
        }
        
        await _next(context); // Ako je sve ok, zahtjev ide dalje
    }
}