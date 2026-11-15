# SQL Injection Incident Response Demo

> **Warning:** This project contains an **intentionally vulnerable** endpoint for teaching purposes. Do not deploy it or reuse its code in production.

A small ASP.NET Core (.NET 10) API that walks through the incident response lifecycle (NIST SP 800-61) for a SQL injection attack. It was built as the practical part of a seminar paper for an information systems security course.

## What it demonstrates

The API exposes two versions of the same user search:

| Endpoint | Query style | Protected by |
|---|---|---|
| `GET /api/users/SearchVulnerable?username=...` | String concatenation (vulnerable) | Detection middleware only |
| `GET /api/users/SearchSecure?username=...` | Parameterized query (secure by design) | The query itself |

`SqlInjectionDetectionMiddleware` sits in front of the vulnerable endpoint and acts as a minimal web application firewall:

- **Detection (phase 2):** it checks every query string value against a list of attack signatures, such as `' OR `, `UNION SELECT`, `DROP TABLE` and SQL comments. On a match it writes a **Critical** structured log entry with the client IP, path, parameter, payload and matched signature.
- **Containment (phase 3):** it stops the request with `403 Forbidden` before it reaches the database.

The secure endpoint opts out of the middleware with `[SkipSqlInjectionDetection]`. That's deliberate: it shows that a parameterized query stays safe on its own, because the payload is treated as a plain username and simply matches nobody.

## Running it

Requires the [.NET 10 SDK](https://dotnet.microsoft.com/download).

```bash
dotnet run
```

The API listens on `http://localhost:5294` and uses an in-memory SQLite database seeded with three users (`admin`, `alice`, `bob`).

Open `SqlIncidentDemo.http` in Visual Studio, Rider, or VS Code (with the REST Client extension) and send the requests in order:

| # | Request | Expected result |
|---|---|---|
| 1 | Normal search, secure endpoint | `200`, returns `alice` |
| 2 | Injection, secure endpoint | `200`, empty list: the attack has no effect |
| 3 | Injection, vulnerable endpoint | `403`, incident logged |
| 4 | `DROP TABLE`, vulnerable endpoint | `403`, incident logged |
| 5 | Normal search, vulnerable endpoint | `200`, returns `bob`: legitimate traffic still passes |

Then open `security_incidents<date>.log` in the project folder to see the forensic record that would be forwarded to a SIEM and the incident response team (CSIRT) in a real environment.

## Known limitations

These are intentional talking points, not oversights. They show why a signature blocklist is a detection layer, not a fix.

- **Blocklists can be bypassed.** Attackers can rewrite a payload so it avoids every listed signature, for example by using other operators, string concatenation, or encodings the filter doesn't anticipate. A blocklist only catches attacks someone has already thought of.
- **False positives.** Legitimate input that happens to contain a signature is blocked, such as text with an apostrophe followed by ` or ` (`Rock 'n' or roll`) or a double dash (`Anne--Marie`).
- **Only the query string is inspected.** Request bodies, headers, cookies and route values are not checked.
- **No escalation or blocking state.** Each request is judged on its own; repeat offenders are not blocked.

The real remedy is the one in `SearchSecure`: parameterized queries (or an ORM that uses them), combined with least-privilege database accounts. Detection middleware is defense in depth on top of that, not instead of it.

## Project structure

```
Program.cs                                    App setup, logging, database seeding
Controllers/UsersController.cs                Vulnerable and secure search endpoints
Middleware/SqlInjectionDetectionMiddleware.cs Signature detection, logging and blocking
SqlIncidentDemo.http                          Ready-made demo requests
```
