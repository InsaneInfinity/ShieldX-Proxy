# 🛡️ Shield-X V7 | Distributed Enterprise Proxy & WAF

[Wersja Polska poniżej]

**Shield-X** is an advanced Reverse Proxy and Web Application Firewall (WAF) built with **.NET 10**. It is designed to protect infrastructure from Layer 7 attacks, automated bots, and unauthorized regional traffic.

## 💎 Key Features (V7 Global Scale)
* **📡 Redis Synchronization:** Shared blacklists and violation counters across multiple server nodes.
* **🌍 Geo-IP Shield:** Integrated country-level blocking powered by **MaxMind GeoLite2**.
* **📊 Live Dashboard:** Real-time attack, ban, and traffic monitoring via **SignalR**.
* **⚡ Non-Blocking I/O:** High-throughput event logging using **System.Threading.Channels** for zero proxy overhead.
* **🛡️ Smart Rate Limiting:** Intelligent request throttling with automated penalty point expiration (Decay).

## 🛠️ Tech Stack
* **Proxy Engine:** Microsoft YARP (Yet Another Reverse Proxy)
* **Real-time Comms:** ASP.NET Core SignalR
* **Data Store:** Redis (Distributed State & Pub/Sub)
* **Geolocation:** MaxMind GeoIP2
* **Platform:** .NET 10.0 / C# 14

## 🚀 Quick Start
1. Configure your Redis `ConnectionString` in `appsettings.json`.
2. Place the `GeoLite2-Country.mmdb` database in the root directory.
3. Run the project: `dotnet run`.
4. Open the monitor panel: `http://localhost:5000/dashboard.html`.

---

## 🇵🇱 Wersja Polska

**Shield-X** to zaawansowany Reverse Proxy i Web Application Firewall (WAF) zbudowany w technologii **.NET 10**. Został zaprojektowany do ochrony infrastruktury przed atakami Layer 7, botami oraz nieautoryzowanym ruchem z określonych regionów świata.

### 💎 Kluczowe Funkcje (V7 Global Scale)
* **📡 Synchronizacja Redis:** Współdzielona czarna lista i liczniki naruszeń między wieloma instancjami serwera.
* **🌍 Geo-IP Shield:** Blokowanie krajów przy użyciu bazy danych **MaxMind GeoLite2**.
* **📊 Live Dashboard:** Monitorowanie ataków i banów w czasie rzeczywistym dzięki **SignalR**.
* **⚡ Non-Blocking I/O:** Logowanie zdarzeń bez spadku wydajności proxy (System.Threading.Channels).
* **🛡️ Smart Rate Limiting:** Inteligentne ograniczanie liczby zapytań z automatycznym wygasaniem punktów karnych (Decay).

---
> *Disclaimer: This project was developed for educational purposes and infrastructure security audits.*