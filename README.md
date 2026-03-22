# 🛡️ Shield-X Proxy V7 — Global Scale Edition

**High-performance .NET 10 WAF & Reverse Proxy with Browser Fingerprinting, Bot Scoring and Global Ban Sync.**

[![.NET](https://img.shields.io/badge/.NET-10.0-512BD4?logo=dotnet)](https://dotnet.microsoft.com)
[![C#](https://img.shields.io/badge/C%23-14-239120?logo=csharp)](https://learn.microsoft.com/dotnet/csharp/)
[![Redis](https://img.shields.io/badge/Redis-Pub%2FSub-DC382D?logo=redis)](https://redis.io)
[![SignalR](https://img.shields.io/badge/SignalR-Real--time-0078D4)](https://learn.microsoft.com/aspnet/signalr)
[![YARP](https://img.shields.io/badge/YARP-Reverse%20Proxy-512BD4)](https://microsoft.github.io/reverse-proxy/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE.txt)

> 💡 **Want deep L7 inspection with Python DPI, body scanning and Log4Shell detection?**
> Check out → [ShieldX-L7-DeepDefense](https://github.com/InsaneInfinity/ShieldX-L7-DeepDefense)

---

## 🗺️ What is Shield-X Proxy?

Shield-X Proxy is a **standalone .NET 10 WAF and reverse proxy** — one process, no Python required. It sits in front of your backend and filters every request through a multi-stage security pipeline before it ever reaches your app.

Designed for **global scale**: bans issued on one node are instantly propagated across the entire cluster via Redis Pub/Sub.

---

## 🏗️ Architecture

```
  Internet
     │
     ▼
┌──────────────────────────────────────────────┐
│          Shield-X Proxy V7 (.NET 10)         │
│                                              │
│  ┌─────────────────────────────────────────┐ │
│  │         Security Pipeline               │ │
│  │                                         │ │
│  │  1. Loopback / Whitelist  → pass        │ │
│  │  2. IP Ban (L1 cache)     → 403         │ │
│  │  3. IP Ban (Redis L2)     → 403         │ │
│  │  4. FP Ban (L1 cache)     → 403         │ │
│  │  5. FP Ban (Redis L2)     → 403         │ │
│  │  6. Geo-IP block          → 403         │ │
│  │  7. Bot Score evaluation  → 403 / pass  │ │
│  │  8. Rate Limit (30/10s)   → 429         │ │
│  │     3x violation          → BAN IP      │ │
│  └─────────────────────────────────────────┘ │
│                                              │
│  YARP Reverse Proxy                          │
│  /proxy/{**} → your backend                  │
│                                              │
│  SignalR Dashboard (flush every 1s)          │
│  Async log writer → logs.txt                 │
└────────────┬─────────────────────────────────┘
             │ Redis Pub/Sub
             ▼
      Other cluster nodes
      (instant ban sync)
```

---

## 🤖 Browser Fingerprinting

Every request gets a **16-char SHA-256 fingerprint** computed from:

| Header | Field |
|---|---|
| `User-Agent` | Browser/client identity |
| `Accept-Language` | Language preferences |
| `Accept-Encoding` | Compression support |
| `Accept` | Content type preferences |
| `Sec-Ch-Ua` | Client hints — browser brand |
| `Sec-Ch-Ua-Mobile` | Mobile indicator |
| `Sec-Ch-Ua-Platform` | OS platform |
| Header order | First 8 header names in order |

The fingerprint is **independent of IP** — bots that rotate IPs or VPNs stay blocked.

---

## 🎯 Bot Scoring (0–100)

Each request is scored based on HTTP stack characteristics:

| Signal | Score |
|---|---|
| Missing `User-Agent` entirely | +40 |
| Known bot UA (`curl`, `wget`, `python-requests`, `go-http-client`, `selenium`, `playwright`, `scrapy`...) | +35 |
| Missing `Accept-Language` | +20 |
| Missing `Accept-Encoding` | +15 |
| Missing `Accept` | +10 |
| `Postman-Token` header present | +10 |
| Missing `Cookie` | +5 |
| **Max score** | **100** |

**Score actions:**

| Condition | Action |
|---|---|
| `score >= BotScoreThreshold` (default 60) | Increment FP violation counter |
| FP violations `>= FingerprintViolationLimit` (default 5) | **BAN fingerprint** |
| FP violations `>= limit` AND `score >= 80` | **BAN fingerprint + BAN IP** |

---

## 🛡️ Blocking Pipeline

```
Request In
    │
    ├─ Loopback IP?          → pass through (dashboard access)
    ├─ Whitelisted IP?       → pass through
    │
    ├─ IP ban in L1 cache?   → 403 (shows remaining ban time in minutes)
    ├─ IP ban in Redis?      → 403 + cache locally
    │
    ├─ FP ban in L1 cache?   → 403
    ├─ FP ban in Redis?      → 403 + cache locally
    │
    ├─ Geo-IP blocked?       → 403 + GeoBlock event
    │
    ├─ Bot score >= threshold → increment FP violations
    │   ├─ violations >= limit → BanFingerprintAsync() + BotEvent
    │   │   └─ score >= 80    → BanIpAsync() + BanEvent
    │   └─ 403
    │
    ├─ pass through → YARP proxy → backend
    │
    └─ Response 429?         → increment IP violations
        └─ violations == 3   → BanIpAsync()
```

---

## 📡 SignalR Events

Events are batched and flushed to the dashboard every **1 second** via `System.Timers.Timer`:

| SignalR Method | Triggered by | Payload includes |
|---|---|---|
| `BanEvent` | IP banned (bot score or rate limit) | `ip`, `country`, `expiry`, `duration` |
| `BotEvent` | Bot score threshold hit or FP banned | `ip`, `fingerprint`, `score`, `country`, `violations`, `expiry` |
| `ViolationEvent` | Rate limit 429 hit | `ip`, `country`, `count`, `threshold` |
| `GeoBlock` | Country blocked | `ip`, `country` |

---

## 📁 Project Structure

```
ShieldX-Proxy/
├── Program.cs               # Full WAF pipeline — single file
├── appsettings.json         # Configuration
├── GeoLite2-Country.mmdb    # MaxMind GeoIP database
├── blacklist.txt            # Static IP blacklist
├── logs.txt                 # Async log output
├── wwwroot/
│   └── dashboard.html       # Real-time SOC dashboard (SignalR)
├── TestStron.csproj
└── TestStron.sln
```

---

## ⚙️ Configuration (`appsettings.json`)

```json
{
  "Redis": { "ConnectionString": "localhost:6379" },
  "GeoIp": {
    "DbPath": "GeoLite2-Country.mmdb",
    "BlockedCountries": ["CN", "RU", "KP", "IR"]
  },
  "BanDuration": "01:00:00",
  "BanCacheTtl": "00:00:10",
  "ViolationDecayTtl": "01:00:00",
  "BotScoreThreshold": 60,
  "FingerprintViolationLimit": 5,
  "TrustedProxies": ["127.0.0.1"],
  "WhitelistedIps": ["your-ip-here"]
}
```

| Parameter | Default | Description |
|---|---|---|
| `Redis.ConnectionString` | `localhost:6379` | Redis server address |
| `GeoIp.BlockedCountries` | `[]` | ISO country codes to block |
| `BanDuration` | `1h` | How long a ban lasts |
| `BanCacheTtl` | `10s` | Local L1 cache TTL for bans |
| `ViolationDecayTtl` | `1h` | How long violation counters live in Redis |
| `BotScoreThreshold` | `60` | Minimum score to trigger violation tracking |
| `FingerprintViolationLimit` | `5` | Violations before fingerprint ban |
| `TrustedProxies` | `[]` | IPs allowed to set `X-Forwarded-For` |
| `WhitelistedIps` | `[]` | IPs that bypass all checks |

---

## 🚀 Quick Start

### Prerequisites
- [.NET 10 SDK](https://dotnet.microsoft.com/download)
- [Redis](https://redis.io/download) running on `localhost:6379`
- `GeoLite2-Country.mmdb` *(included in repo — see GeoIP note below)*

```bash
git clone https://github.com/InsaneInfinity/ShieldX-Proxy.git
cd ShieldX-Proxy

dotnet run
# Dashboard → http://localhost:5000/dashboard.html
```

**No Redis?** Shield-X uses `AbortOnConnectFail = false` — it starts anyway and operates in local-only mode. Ban sync across nodes is disabled but the full pipeline still works.

### Change the proxy backend

Edit `Program.cs` — find the cluster config and replace `httpbin.org` with your backend:

```csharp
{ "dest1", new DestinationConfig { Address = "https://your-backend.com" } }
```

Requests to `/proxy/anything` are forwarded to `/anything` on your backend (prefix stripped automatically).

---

## 🌍 GeoIP Note

`GeoLite2-Country.mmdb` is included in this repo for convenience. It is subject to [MaxMind's GeoLite2 license](https://www.maxmind.com/en/geolite2/eula). To get the latest database:

1. Register at [maxmind.com](https://www.maxmind.com)
2. Download **GeoLite2-Country** (`.mmdb` format)
3. Replace the file in the repo root

---

## 🧪 Testing

```bash
# Normal request — should pass through to httpbin.org
curl http://localhost:5000/proxy/get

# Simulate bot (curl UA triggers +35 score)
curl -v http://localhost:5000/proxy/get

# Simulate high-score bot (missing most headers)
curl --no-alpn -A "" http://localhost:5000/proxy/get

# Rate limit — 31 requests in 10 seconds triggers 429
for i in $(seq 1 35); do curl -s http://localhost:5000/proxy/get > /dev/null; done

# Check dashboard
open http://localhost:5000/dashboard.html
```

---

## 🇵🇱 Opis projektu

Shield-X Proxy V7 to samodzielny WAF i reverse proxy napisany w .NET 10 — bez żadnych zależności od Pythona.

Każde zapytanie przechodzi przez 8-etapowy pipeline: whitelist → ban IP (L1 cache + Redis) → ban fingerprint (L1 cache + Redis) → Geo-IP → Bot Score → rate limit. Browser Fingerprinting tworzy 16-znakowy hash SHA-256 z nagłówków HTTP i ich kolejności — boty zmieniające IP lub VPN pozostają zablokowane. System Bot Scoring przyznaje punkty za podejrzane sygnały (brak UA, znane narzędzia jak curl/selenium/playwright, brak standardowych nagłówków przeglądarki). Po przekroczeniu progu 5 naruszeń ban jest nakładany na fingerprint, a przy score ≥ 80 — także na IP.

Bany są synchronizowane przez Redis Pub/Sub — każdy węzeł klastra natychmiast wie o nowym banie. Dashboard SignalR odbiera zdarzenia paczkowane co 1 sekundę. Logi zapisywane są asynchronicznie przez bounded channel do pliku `logs.txt`.

---

## ⚖️ License

MIT — free to use, modify and distribute. See [LICENSE.txt](LICENSE.txt) for details.

> Disclaimer: This project was developed for educational purposes and infrastructure security audits. Always ensure compliance with local laws when deploying security tools.

---

Built with ❤️ — because "standard" protection is never enough.
