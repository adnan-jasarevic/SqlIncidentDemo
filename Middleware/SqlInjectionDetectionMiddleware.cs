using System.Text.RegularExpressions;

namespace SqlIncidentDemo.Middleware;

/// Marks an endpoint that is safe by design and does not need signature-based
/// SQL injection detection.
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method)]
public sealed class SkipSqlInjectionDetectionAttribute : Attribute;

/// A minimal signature-based filter (a "mini WAF"). It inspects query string
/// values, logs a critical incident when an attack signature matches, and blocks
/// the request before it reaches vulnerable code.
///
/// A blocklist like this is a detection and containment layer, not a fix:
/// it can be bypassed (see README, "Known limitations"). The real fix is the
/// parameterized query in UsersController.SearchSecure.
public partial class SqlInjectionDetectionMiddleware
{
    private static readonly string[] Signatures =
    [
        "' OR ",        // tautologies such as ' OR '1'='1 or ' OR 'a'='a
        "UNION SELECT", // reading other tables
        "DROP TABLE",   // destructive statements
        "--",           // comment out the rest of the query
        "/*",           // inline comments, often used to hide keywords
    ];

    private readonly RequestDelegate _next;
    private readonly ILogger<SqlInjectionDetectionMiddleware> _logger;

    public SqlInjectionDetectionMiddleware(RequestDelegate next, ILogger<SqlInjectionDetectionMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        if (context.GetEndpoint()?.Metadata.GetMetadata<SkipSqlInjectionDetectionAttribute>() is not null)
        {
            await _next(context);
            return;
        }

        // Inspect the values exactly as model binding will see them: the
        // framework has already URL-decoded them, including '+' as a space.
        foreach (var (key, values) in context.Request.Query)
        {
            foreach (var value in values)
            {
                if (value is null)
                {
                    continue;
                }

                var signature = FindSignature(value);
                if (signature is null)
                {
                    continue;
                }

                var clientIp = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";

                // Phase 2: detection and structured incident logging.
                _logger.LogCritical(
                    "INCIDENT DETECTED: SQL injection attempt from {ClientIp} on {Path}. " +
                    "Parameter: {Parameter}. Payload: {Payload}. Signature: {Signature}",
                    clientIp, context.Request.Path.Value, Sanitize(key), Sanitize(value), signature);

                // Phase 3: containment. Stop the request before it reaches the database.
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                await context.Response.WriteAsync(
                    "SECURITY ALERT: Malicious SQL pattern detected. The request was blocked and the incident was logged.");
                return;
            }
        }

        await _next(context);
    }

    private static string? FindSignature(string value)
    {
        // Collapse runs of whitespace so "UNION    SELECT" still matches.
        var normalized = Whitespace().Replace(value, " ");
        return Signatures.FirstOrDefault(s => normalized.Contains(s, StringComparison.OrdinalIgnoreCase));
    }

    // Strip control characters such as newlines so an attacker cannot forge
    // extra lines in the log file.
    private static string Sanitize(string value) => ControlCharacters().Replace(value, "?");

    [GeneratedRegex(@"\s+")]
    private static partial Regex Whitespace();

    [GeneratedRegex(@"\p{Cc}")]
    private static partial Regex ControlCharacters();
}
