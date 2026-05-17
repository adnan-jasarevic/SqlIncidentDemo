# Praktični dio: Detekcija i izolacija SQL Injection napada (Incident Response)

Ova aplikacija predstavlja praktični dodatak seminarskom radu iz predmeta **Sigurnost informacionih sistema**. Cilj projekta je tehnička demonstracija faza životnog ciklusa upravljanja incidentima (Incident Response Lifecycle) unutar .NET Core okruženja.

## Kako funkcioniše sigurnosni mehanizam?
Kao prva linija odbrane, implementiran je `SqlInjectionDetectionMiddleware`. Ovaj komponent djeluje kao mini WAF (Web Application Firewall):
- **Detekcija (Faza 2):** Skener analizira svaki dolazni HTTP zahtjev. Ukoliko u URL parametrima prepozna maliciozne obrasce (tzv. potpise napada poput `OR '1'='1` ili `DROP TABLE`), generiše se *Critical* log koji sadrži IP adresu napadača, vrijeme i tačan payload.
- **Izolacija (Faza 3):** Middleware trenutno prekida izvršavanje zahtjeva, odbacuje ga sa status kodom `403 Forbidden` i sprječava da maliciozni kod uopšte dođe do ranjivih dijelova aplikacije ili baze podataka.

## Uputstvo za pokretanje i testiranje
Projekat koristi SQLite In-Memory bazu.

1. Otvorite folder u terminalu i pokrenite projekat komandom:
   ```bash
   dotnet run
   ```
2. Otvorite fajl `test_napad.http` u Visual Studio Code-u (potrebna je REST Client ekstenzija).
3. Pokrenite **Zahtjev 1** da potvrdite da aplikacija i baza normalno rade.
4. Pokrenite **Zahtjev 3** ili **Zahtjev 4** da simulirate SQL Injection napad.
5. Dobit ćete sigurnosno upozorenje (Status 403).
6. U root folderu projekta otvorite generisani fajl `security_incidents.log` kako biste pregledali forenzički zapis koji bi se u realnom okruženju poslao SIEM sistemu i CSIRT timu.
