# 🛡️ SHIELD-X V7: Global Scale Edition

SHIELD-X is a high-performance, distributed Web Application Firewall (WAF) and Anti-Bot system built with **.NET 10**, Redis, and YARP. Version 7 introduces advanced Browser Fingerprinting and an intelligent Bot Scoring engine to protect your infrastructure from modern automated threats.

## 🚀 Key Features

* **Global Ban Sync (Redis Pub/Sub):** Bans issued on one node are instantly propagated across the entire cluster.
* **L1/L2 Tiered Caching:** Uses `IMemoryCache` (L1) and Redis (L2) to ensure sub-millisecond lookups and protect the database from DoS.
* **Advanced Browser Fingerprinting:** Identifies bots based on unique HTTP stack characteristics and header ordering, making IP/VPN rotation ineffective.
* **Intelligent Bot Scoring (0-100):** Evaluates every request's risk. Suspicious signals (e.g., curl, missing Accept headers) are scored and blocked upon reaching a threshold.
* **Fail-Open Architecture:** Integrated circuit breakers ensure that a Redis failure does not bring down your application.
* **Real-time SignalR Dashboard:** Live event monitoring with built-in event batching (throttling) to keep the UI responsive even during heavy attacks.

## 🛡️ Blocking Logic

1. **Whitelisting:** Trusted IPs bypass all security checks.
2. **L1 Cache Check:** Instant rejection if the IP or Fingerprint is on the local "hot-list".
3. **Geo-IP Filtering:** Blocking based on country codes (MaxMind).
4. **Bot Score Evaluation:** High-risk requests (`score >= 80`) trigger an immediate dual ban on both IP and Fingerprint.
5. **Rate Limiting:** Precision control over request frequency (default: 30 req/10s).

## 🛠️ Tech Stack

* **Proxy Engine:** Microsoft YARP (Yet Another Reverse Proxy)
* **Real-time Comms:** ASP.NET Core SignalR
* **Data Store:** Redis (Distributed State & Pub/Sub)
* **Geolocation:** MaxMind GeoIP2
* **Platform:** .NET 10.0 / C# 14

## 🚀 Quick Start

1. Configure your `appsettings.json` (see Configuration below).
2. Download and place the `GeoLite2-Country.mmdb` database in the root directory (see GeoIP Setup below).
3. Run the project: `dotnet run`.
4. Open the monitor panel: `http://localhost:5000/dashboard.html`.

## ⚙️ Configuration (`appsettings.json`)

```json
{
  "Redis": { "ConnectionString": "localhost:6379" },
  "GeoIp": {
    "DbPath": "GeoLite2-Country.mmdb",
    "BlockedCountries": ["CN", "RU"]
  },
  "BotScoreThreshold": 60,
  "FingerprintViolationLimit": 5,
  "TrustedProxies": ["127.0.0.1"],
  "WhitelistedIps": ["your-ip-here"]
}
```

| Parameter | Description | Default |
|-----------|-------------|---------|
| `Redis.ConnectionString` | Redis server address | `localhost:6379` |
| `GeoIp.BlockedCountries` | ISO country codes to block | `[]` |
| `BotScoreThreshold` | Score threshold for immediate ban | `60` |
| `FingerprintViolationLimit` | Violations before fingerprint ban | `5` |
| `TrustedProxies` | IPs allowed to set X-Forwarded-For | `[]` |
| `WhitelistedIps` | IPs that bypass all checks | `[]` |

## 🌍 GeoIP Setup

The `GeoLite2-Country.mmdb` file is **not included** in this repository due to MaxMind's license restrictions. You need to download it manually:

1. Register for a free account at https://www.maxmind.com
2. Download the **GeoLite2-Country** database (`.mmdb` format)
3. Place the `GeoLite2-Country.mmdb` file in the root directory of the project

---

## 🛡️ SHIELD-X V7: Edycja Global Scale (PL)

SHIELD-X to wysokowydajny, rozproszony system ochrony aplikacji internetowych (WAF) oraz system anty-botowy zbudowany w oparciu o **.NET 10**, Redis i YARP. Wersja V7 wprowadza zaawansowany silnik Browser Fingerprinting oraz inteligentny system Bot Scoringu, aby chronić Twoją infrastrukturę przed nowoczesnymi, zautomatyzowanymi zagrożeniami.

### 🚀 Kluczowe Funkcje

* **Globalna Synchronizacja Banów (Redis Pub/Sub):** Blokada na jednym węźle jest natychmiast propagowana do całego klastra.
* **Dwuwarstwowy Caching L1/L2:** Wykorzystanie `IMemoryCache` (L1) oraz Redisa (L2) zapewnia minimalne opóźnienia i chroni bazę danych przed atakami DoS.
* **Browser Fingerprinting:** Identyfikacja botów na podstawie unikalnych cech stosu HTTP i kolejności nagłówków, co sprawia, że zmiana IP/VPN staje się nieskuteczna.
* **Bot Scoring (0-100):** Ocena ryzyka każdego zapytania. Podejrzane sygnały (np. curl, brak nagłówków Accept) są punktowane i blokowane po przekroczeniu progu.
* **Architektura Fail-Open:** Wbudowane bezpieczniki (circuit breakers) gwarantują, że awaria Redisa nie unieruchomi Twojej aplikacji.
* **Dashboard SignalR:** Monitoring zdarzeń na żywo z wbudowanym mechanizmem paczkowania (throttlingu), aby zachować płynność UI nawet podczas silnych ataków.

### 🛡️ Logika Blokowania

1. **Whitelista:** Zaufane adresy IP omijają wszystkie filtry bezpieczeństwa.
2. **L1 Cache Check:** Natychmiastowe odrzucenie, jeśli IP lub Fingerprint znajduje się na lokalnej "gorącej liście".
3. **Geo-IP:** Blokada na podstawie kodów krajów (MaxMind).
4. **Bot Score:** Analiza nagłówków. Jeśli `score >= 80`, banowane jest zarówno IP, jak i Fingerprint.
5. **Rate Limiting:** Precyzyjna kontrola częstotliwości żądań (domyślnie 30 req/10s).

### ⚙️ Konfiguracja (`appsettings.json`)

```json
{
  "Redis": { "ConnectionString": "localhost:6379" },
  "GeoIp": {
    "DbPath": "GeoLite2-Country.mmdb",
    "BlockedCountries": ["CN", "RU"]
  },
  "BotScoreThreshold": 60,
  "FingerprintViolationLimit": 5,
  "TrustedProxies": ["127.0.0.1"],
  "WhitelistedIps": ["twoje-ip"]
}
```

| Parametr | Opis | Domyślnie |
|----------|------|-----------|
| `Redis.ConnectionString` | Adres serwera Redis | `localhost:6379` |
| `GeoIp.BlockedCountries` | Kody ISO krajów do zablokowania | `[]` |
| `BotScoreThreshold` | Próg punktowy dla natychmiastowego bana | `60` |
| `FingerprintViolationLimit` | Naruszenia przed banem fingerprint | `5` |
| `TrustedProxies` | IP uprawnione do ustawiania X-Forwarded-For | `[]` |
| `WhitelistedIps` | IP omijające wszystkie filtry | `[]` |

### 🌍 Konfiguracja GeoIP

Plik `GeoLite2-Country.mmdb` **nie jest dołączony** do repozytorium ze względu na licencję MaxMind. Należy pobrać go ręcznie:

1. Zarejestruj darmowe konto na https://www.maxmind.com
2. Pobierz bazę **GeoLite2-Country** (format `.mmdb`)
3. Umieść plik `GeoLite2-Country.mmdb` w katalogu głównym projektu

---

> *Disclaimer: This project was developed for educational purposes and infrastructure security audits. Always ensure compliance with local laws and regulations when deploying security tools.*
