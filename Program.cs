// =====================================================================
// SHIELD-X V7 – "Global Scale" Edition + Browser Fingerprinting
// =====================================================================
// Zmiany względem poprzedniej wersji:
//   + ComputeFingerprint()  – hash SHA-256 z nagłówków HTTP
//   + BotScore()            – punktacja podejrzanych sygnałów (0-100)
//   + Bany per fingerprint  – Redis: shieldx:ban:fp:{hash}
//   + Violations per fp     – Redis: shieldx:violations:fp:{hash}
//   + Dashboard events      – BotEvent wysyłany do SignalR
//   + Whitelist IP          – zaufane IP nigdy nie dostają bana
//   + YARP path transform   – /proxy/get → /get na backendzie
// =====================================================================

using System.Threading.RateLimiting;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.SignalR;
using Microsoft.Extensions.Caching.Memory;
using Yarp.ReverseProxy.Configuration;
using System.Net;
using System.Collections.Concurrent;
using System.Threading.Channels;
using System.Security.Cryptography;
using System.Text;
using StackExchange.Redis;
using MaxMind.GeoIP2;

var builder = WebApplication.CreateBuilder(args);
var cfg     = builder.Configuration;

TimeSpan banDuration       = cfg.GetValue<TimeSpan?>("BanDuration")        ?? TimeSpan.FromHours(1);
TimeSpan violationDecayTtl = cfg.GetValue<TimeSpan?>("ViolationDecayTtl")  ?? TimeSpan.FromHours(1);
TimeSpan banCacheTtl       = cfg.GetValue<TimeSpan?>("BanCacheTtl")        ?? TimeSpan.FromSeconds(10);
string   redisConn         = cfg.GetValue<string>("Redis:ConnectionString") ?? "localhost:6379";
string   geoDbPath         = cfg.GetValue<string>("GeoIp:DbPath")           ?? "GeoLite2-Country.mmdb";
int      botScoreThreshold = cfg.GetValue<int?>("BotScoreThreshold")        ?? 60;
int      fpViolationLimit  = cfg.GetValue<int?>("FingerprintViolationLimit") ?? 5;

var blockedCountries = cfg.GetSection("GeoIp:BlockedCountries")
                          .Get<HashSet<string>>() ?? new HashSet<string>();

var trustedProxies   = cfg.GetSection("TrustedProxies")
                          .Get<HashSet<string>>() ?? new HashSet<string>();

var whitelistedIps   = cfg.GetSection("WhitelistedIps")
                          .Get<HashSet<string>>() ?? new HashSet<string>();

// ── Redis ─────────────────────────────────────────────────────────────
var redisOpts = ConfigurationOptions.Parse(redisConn);
redisOpts.AbortOnConnectFail = false;
var redis      = await ConnectionMultiplexer.ConnectAsync(redisOpts);
var db         = redis.GetDatabase();
var subscriber = redis.GetSubscriber();

// ── Geo-IP ────────────────────────────────────────────────────────────
DatabaseReader? geoReader = null;
if (File.Exists(geoDbPath))
{
    geoReader = new DatabaseReader(geoDbPath);
    Console.WriteLine($"[GEO-IP] Baza załadowana: {geoDbPath} | Blokowane: {string.Join(", ", blockedCountries)}");
}
else
{
    Console.ForegroundColor = ConsoleColor.Yellow;
    Console.WriteLine($"[GEO-IP] UWAGA: Brak pliku {geoDbPath} – blokowanie krajów wyłączone.");
    Console.ResetColor();
}

// ── Log channel ───────────────────────────────────────────────────────
var logChannel = Channel.CreateBounded<string>(new BoundedChannelOptions(4096)
{
    FullMode = BoundedChannelFullMode.DropOldest
});

var logWriterTask = Task.Run(async () =>
{
    await foreach (var entry in logChannel.Reader.ReadAllAsync())
    {
        try   { await File.AppendAllTextAsync("logs.txt", entry + Environment.NewLine); }
        catch { }
    }
});

// ── Services ──────────────────────────────────────────────────────────
builder.Services.AddSignalR();
builder.Services.AddDirectoryBrowser();
builder.Services.AddMemoryCache();

// POPRAWKA: Transformacja ścieżki – usuwa prefiks /proxy/ przed wysłaniem do backendu
// Przykład: /proxy/get → /get na docelowym serwerze
var routes = new[]
{
    new RouteConfig
    {
        RouteId    = "route1",
        ClusterId  = "cluster1",
        Match      = new RouteMatch { Path = "/proxy/{**catch-all}" },
        Transforms = new List<Dictionary<string, string>>
        {
            new Dictionary<string, string> { { "PathPattern", "/{**catch-all}" } }
        }
    }
};

var clusters = new[]
{
    new ClusterConfig
    {
        ClusterId    = "cluster1",
        Destinations = new Dictionary<string, DestinationConfig>
        {
            // httpbin.org – idealne do testów, zwraca JSON z nagłówkami i IP
            // Zmień na własny backend w produkcji
            { "dest1", new DestinationConfig { Address = "https://httpbin.org" } }
        },
        HttpRequest = new Yarp.ReverseProxy.Forwarder.ForwarderRequestConfig
        {
            ActivityTimeout = TimeSpan.FromSeconds(30)
        }
    }
};

builder.Services.AddReverseProxy().LoadFromMemory(routes, clusters);

builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.AddPolicy("fixed-policy", httpContext =>
    {
        string clientIp = ResolveClientIp(httpContext, trustedProxies);
        if (IPAddress.TryParse(clientIp, out var a) && IPAddress.IsLoopback(a))
            return RateLimitPartition.GetNoLimiter("localhost");

        return RateLimitPartition.GetFixedWindowLimiter(clientIp,
            _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 30,
                Window      = TimeSpan.FromSeconds(10)
            });
    });
});

var app = builder.Build();

// ── Helpers ───────────────────────────────────────────────────────────

static string ResolveClientIp(HttpContext ctx, HashSet<string> trustedProxies)
{
    var remoteIp = ctx.Connection.RemoteIpAddress?.ToString();
    if (remoteIp != null && trustedProxies.Contains(remoteIp))
    {
        var forwarded = ctx.Request.Headers["X-Forwarded-For"].FirstOrDefault();
        if (!string.IsNullOrWhiteSpace(forwarded))
        {
            var first = forwarded.Split(',')[0].Trim();
            if (IPAddress.TryParse(first, out _)) return first;
        }
    }
    return remoteIp ?? "::1";
}

string? ResolveCountry(string ip)
{
    if (geoReader is null) return null;
    if (!IPAddress.TryParse(ip, out var addr) || IPAddress.IsLoopback(addr)) return null;
    try   { return geoReader.Country(ip).Country.IsoCode; }
    catch { return null; }
}

void Logger(string message, ConsoleColor color = ConsoleColor.Gray)
{
    string logEntry = $"[{DateTime.Now:HH:mm:ss}] {message}";
    Console.ForegroundColor = color;
    Console.WriteLine(logEntry);
    Console.ResetColor();
    logChannel.Writer.TryWrite(logEntry);
}

// ── Fingerprinting ────────────────────────────────────────────────────

static string ComputeFingerprint(HttpRequest req)
{
    var ua      = req.Headers["User-Agent"].ToString();
    var al      = req.Headers["Accept-Language"].ToString();
    var ae      = req.Headers["Accept-Encoding"].ToString();
    var acc     = req.Headers["Accept"].ToString();
    var sec     = req.Headers["Sec-Ch-Ua"].ToString();
    var secMob  = req.Headers["Sec-Ch-Ua-Mobile"].ToString();
    var secPlat = req.Headers["Sec-Ch-Ua-Platform"].ToString();
    var order   = string.Join(",", req.Headers.Keys.Take(8));

    var raw  = $"{ua}|{al}|{ae}|{acc}|{sec}|{secMob}|{secPlat}|{order}";
    var hash = SHA256.HashData(Encoding.UTF8.GetBytes(raw));
    return Convert.ToHexString(hash)[..16];
}

static int ComputeBotScore(HttpRequest req)
{
    int score = 0;
    var ua = req.Headers["User-Agent"].ToString();

    if (string.IsNullOrWhiteSpace(ua))
    {
        score += 40;
    }
    else
    {
        string[] botSignatures =
        [
            "curl", "wget", "python-requests", "python-urllib",
            "go-http-client", "java/", "okhttp", "axios",
            "libwww-perl", "scrapy", "bot", "crawler", "spider",
            "headless", "phantomjs", "selenium", "playwright"
        ];
        if (botSignatures.Any(sig => ua.Contains(sig, StringComparison.OrdinalIgnoreCase)))
            score += 35;
    }

    if (string.IsNullOrWhiteSpace(req.Headers["Accept-Language"]))  score += 20;
    if (string.IsNullOrWhiteSpace(req.Headers["Accept-Encoding"]))  score += 15;
    if (string.IsNullOrWhiteSpace(req.Headers["Accept"]))           score += 10;
    if (!string.IsNullOrWhiteSpace(req.Headers["Postman-Token"]))   score += 10;
    if (string.IsNullOrWhiteSpace(req.Headers["Cookie"]))           score += 5;

    return Math.Min(score, 100);
}

// ── Circuit Breaker ───────────────────────────────────────────────────

async Task<bool> IsBannedInRedisAsync(string key)
{
    try   { return (await db.StringGetAsync(key)).HasValue; }
    catch (RedisException ex)
    {
        Logger($"[REDIS] Błąd ban-check {key}: {ex.Message}", ConsoleColor.DarkYellow);
        return false;
    }
}

async Task<int> IncrementAsync(string key)
{
    try
    {
        long count = await db.StringIncrementAsync(key);
        if (count == 1) await db.KeyExpireAsync(key, violationDecayTtl);
        return (int)count;
    }
    catch (RedisException ex)
    {
        Logger($"[REDIS] Błąd increment {key}: {ex.Message}", ConsoleColor.DarkYellow);
        return 0;
    }
}

// ── Event buffer ──────────────────────────────────────────────────────
var eventBuffer = new ConcurrentQueue<object>();

async Task BanIpAsync(string ip, string? country, IMemoryCache banCache)
{
    try
    {
        await db.StringSetAsync($"shieldx:ban:{ip}", "1", banDuration);
        await subscriber.PublishAsync(RedisChannel.Literal("shieldx:bans"), ip);
    }
    catch (RedisException ex)
    {
        Logger($"[REDIS] Błąd zapisu bana IP {ip}: {ex.Message}", ConsoleColor.DarkYellow);
    }

    banCache.Set($"ban:{ip}", true, banDuration);
    Logger($"[!!!] AUTO-BAN IP: {ip} [{country ?? "??"}] → {banDuration.TotalMinutes:0} min",
           ConsoleColor.Red);

    eventBuffer.Enqueue(new
    {
        type     = "ban",
        ip,
        country  = country ?? "??",
        expiry   = DateTimeOffset.UtcNow.Add(banDuration).ToString("HH:mm:ss"),
        duration = (int)banDuration.TotalMinutes
    });
}

async Task BanFingerprintAsync(string fp, string ip, string? country,
                               int score, IMemoryCache banCache)
{
    try
    {
        await db.StringSetAsync($"shieldx:ban:fp:{fp}", ip, banDuration);
        await subscriber.PublishAsync(RedisChannel.Literal("shieldx:bans:fp"), fp);
    }
    catch (RedisException ex)
    {
        Logger($"[REDIS] Błąd zapisu bana FP {fp}: {ex.Message}", ConsoleColor.DarkYellow);
    }

    banCache.Set($"ban:fp:{fp}", true, banDuration);
    Logger($"[!!!] AUTO-BAN FP: {fp} (score={score}) IP={ip} [{country ?? "??"}] → {banDuration.TotalMinutes:0} min",
           ConsoleColor.Magenta);

    eventBuffer.Enqueue(new
    {
        type        = "bot",
        ip,
        fingerprint = fp,
        score,
        country     = country ?? "??",
        expiry      = DateTimeOffset.UtcNow.Add(banDuration).ToString("HH:mm:ss"),
        duration    = (int)banDuration.TotalMinutes
    });
}

// ── Redis Pub/Sub ─────────────────────────────────────────────────────
await subscriber.SubscribeAsync(RedisChannel.Literal("shieldx:bans"), (_, ip) =>
{
    Logger($"[SYNC] Ban IP odebrany od węzła: {ip}", ConsoleColor.Magenta);
    var cache = app.Services.GetRequiredService<IMemoryCache>();
    cache.Set($"ban:{(string)ip!}", true, banDuration);
});

await subscriber.SubscribeAsync(RedisChannel.Literal("shieldx:bans:fp"), (_, fp) =>
{
    Logger($"[SYNC] Ban FP odebrany od węzła: {fp}", ConsoleColor.Magenta);
    var cache = app.Services.GetRequiredService<IMemoryCache>();
    cache.Set($"ban:fp:{(string)fp!}", true, banDuration);
});

// =====================================================================
// PIPELINE
// =====================================================================

app.UseStaticFiles();
app.MapGet("/", () => Results.Redirect("/dashboard.html"));
app.MapHub<ShieldXHub>("/shieldx-hub");

var hubCtx   = app.Services.GetRequiredService<IHubContext<ShieldXHub>>();
var banCache = app.Services.GetRequiredService<IMemoryCache>();

// Flush timer – paczki SignalR co 1 sekundę
var flushTimer = new System.Timers.Timer(1000);
flushTimer.Elapsed += async (_, _) =>
{
    if (eventBuffer.IsEmpty) return;
    var batch = new List<object>();
    while (eventBuffer.TryDequeue(out var ev)) batch.Add(ev);
    try
    {
        foreach (var ev in batch)
        {
            dynamic d    = ev;
            string  type = (string)d.type;
            switch (type)
            {
                case "ban":
                    await hubCtx.Clients.All.SendAsync("BanEvent", ev);
                    break;
                case "violation":
                    await hubCtx.Clients.All.SendAsync("ViolationEvent", ev);
                    break;
                case "geoblock":
                    await hubCtx.Clients.All.SendAsync("GeoBlock", ev);
                    break;
                case "bot":
                    await hubCtx.Clients.All.SendAsync("BotEvent", ev);
                    break;
            }
        }
    }
    catch { }
};
flushTimer.Start();

// ── Middleware antyfrodowy ─────────────────────────────────────────────
app.Use(async (context, next) =>
{
    string clientIp = ResolveClientIp(context, trustedProxies);

    if (IPAddress.TryParse(clientIp, out var addr) && IPAddress.IsLoopback(addr))
    {
        await next();
        return;
    }

    if (whitelistedIps.Contains(clientIp))
    {
        await next();
        return;
    }

    string? country     = ResolveCountry(clientIp);
    string  fingerprint = ComputeFingerprint(context.Request);
    int     botScore    = ComputeBotScore(context.Request);

    // ── 1. Sprawdź ban IP ──────────────────────────────────────────────
    if (!banCache.TryGetValue($"ban:{clientIp}", out _))
    {
        if (await IsBannedInRedisAsync($"shieldx:ban:{clientIp}"))
            banCache.Set($"ban:{clientIp}", true, banCacheTtl);
    }

    if (banCache.TryGetValue($"ban:{clientIp}", out _))
    {
        var ttl  = await db.KeyTimeToLiveAsync($"shieldx:ban:{clientIp}");
        double m = ttl?.TotalMinutes ?? 0;
        context.Response.StatusCode = 403;
        await context.Response.WriteAsync($"IP ZABLOKOWANE. Ban wygasa za {m:0.0} minut.");
        return;
    }

    // ── 2. Sprawdź ban fingerprint ────────────────────────────────────
    if (!banCache.TryGetValue($"ban:fp:{fingerprint}", out _))
    {
        if (await IsBannedInRedisAsync($"shieldx:ban:fp:{fingerprint}"))
            banCache.Set($"ban:fp:{fingerprint}", true, banCacheTtl);
    }

    if (banCache.TryGetValue($"ban:fp:{fingerprint}", out _))
    {
        Logger($"[BOT-BAN] FP={fingerprint} IP={clientIp} [{country ?? "??"}] zablokowany",
               ConsoleColor.Magenta);
        context.Response.StatusCode = 403;
        await context.Response.WriteAsync("Zablokowano – wykryto automatyczny klient.");
        return;
    }

    // ── 3. Sprawdź Geo-IP ─────────────────────────────────────────────
    if (country is not null && blockedCountries.Contains(country))
    {
        context.Response.StatusCode = 403;
        Logger($"[GEO] Zablokowano {clientIp} [{country}]", ConsoleColor.DarkRed);
        await context.Response.WriteAsync($"Dostęp zablokowany dla regionu: {country}");
        eventBuffer.Enqueue(new { type = "geoblock", ip = clientIp, country });
        return;
    }

    // ── 4. Ocena Bot Score ────────────────────────────────────────────
    if (botScore >= botScoreThreshold)
    {
        int fpViolations = await IncrementAsync($"shieldx:violations:fp:{fingerprint}");

        Logger($"[BOT] Score={botScore} FP={fingerprint} IP={clientIp} [{country ?? "??"}] " +
               $"Naruszenia: {fpViolations}/{fpViolationLimit}",
               ConsoleColor.DarkMagenta);

        eventBuffer.Enqueue(new
        {
            type        = "bot",
            ip          = clientIp,
            fingerprint,
            score       = botScore,
            country     = country ?? "??",
            violations  = fpViolations,
            threshold   = fpViolationLimit,
            expiry      = "",
            duration    = 0
        });

        if (fpViolations >= fpViolationLimit)
        {
            await BanFingerprintAsync(fingerprint, clientIp, country, botScore, banCache);
            if (botScore >= 80)
                await BanIpAsync(clientIp, country, banCache);
        }

        context.Response.StatusCode = 403;
        await context.Response.WriteAsync("Zablokowano – wykryto automatyczny klient.");
        return;
    }

    await next();

    // ── 5. Obsługa 429 (rate limit) ───────────────────────────────────
    if (context.Response.StatusCode == 429)
    {
        int violations = await IncrementAsync($"shieldx:violations:{clientIp}");
        Logger($"[!] OSTRZEZENIE: {clientIp} [{country ?? "??"}] (Przewinienie: {violations}/3)",
               ConsoleColor.Yellow);

        eventBuffer.Enqueue(new
        {
            type      = "violation",
            ip        = clientIp,
            country   = country ?? "??",
            count     = violations,
            threshold = 3
        });

        if (violations == 3)
            await BanIpAsync(clientIp, country, banCache);
    }
});

app.UseRateLimiter();

app.MapReverseProxy(proxy =>
{
    proxy.Use(async (context, next) =>
    {
        var ip = ResolveClientIp(context, trustedProxies);
        Logger(
            $"[OK] {context.Request.Method} {context.Request.Path} " +
            $"od {ip} [{ResolveCountry(ip) ?? "??"}]",
            ConsoleColor.Green);
        await next();
    });
}).RequireRateLimiting("fixed-policy");

// ── Graceful shutdown ─────────────────────────────────────────────────
var lifetime = app.Services.GetRequiredService<IHostApplicationLifetime>();
lifetime.ApplicationStopping.Register(() =>
{
    flushTimer.Stop();
    flushTimer.Dispose();
    logChannel.Writer.Complete();
    logWriterTask.Wait(TimeSpan.FromSeconds(5));
    geoReader?.Dispose();
    redis.Dispose();
});

Logger("=== SHIELD-X V7 [GLOBAL SCALE + FINGERPRINTING] URUCHOMIONY ===", ConsoleColor.Cyan);
Logger($"    Redis              : {redisConn}",                                                                    ConsoleColor.Cyan);
Logger($"    Ban TTL            : {banDuration.TotalMinutes:0} min",                                              ConsoleColor.Cyan);
Logger($"    Ban cache TTL      : {banCacheTtl.TotalSeconds:0} s",                                                ConsoleColor.Cyan);
Logger($"    Violation TTL      : {violationDecayTtl.TotalMinutes:0} min",                                        ConsoleColor.Cyan);
Logger($"    Bot score threshold: {botScoreThreshold}/100",                                                        ConsoleColor.Cyan);
Logger($"    FP violation limit : {fpViolationLimit}",                                                            ConsoleColor.Cyan);
Logger($"    Trusted proxies    : {(trustedProxies.Count > 0 ? string.Join(", ", trustedProxies) : "brak")}",    ConsoleColor.Cyan);
Logger($"    Whitelisted IPs    : {(whitelistedIps.Count > 0 ? string.Join(", ", whitelistedIps) : "brak")}",    ConsoleColor.Cyan);
Logger($"    Geo-IP             : {(geoReader is not null ? $"aktywny ({blockedCountries.Count} krajów)" : "wyłączony")}", ConsoleColor.Cyan);
Logger($"    Proxy cel          : httpbin.org (zmień w kodzie na własny backend)",                                ConsoleColor.Cyan);
Logger($"    Dashboard          : http://localhost:5000/dashboard.html",                                           ConsoleColor.Cyan);
app.Run();

// ── SignalR Hub ───────────────────────────────────────────────────────
public class ShieldXHub : Hub
{
    public async Task RequestStats()
    {
        await Clients.Caller.SendAsync("StatsResponse", new
        {
            timestamp = DateTime.UtcNow.ToString("o"),
            message   = "Połączono z Shield-X V7 [FINGERPRINTING]"
        });
    }
}
// =====================================================================
// SHIELD-X V7 – "Global Scale" Edition + Browser Fingerprinting
// =====================================================================
// Zmiany względem poprzedniej wersji:
//   + ComputeFingerprint()  – hash SHA-256 z nagłówków HTTP
//   + BotScore()            – punktacja podejrzanych sygnałów (0-100)
//   + Bany per fingerprint  – Redis: shieldx:ban:fp:{hash}
//   + Violations per fp     – Redis: shieldx:violations:fp:{hash}
//   + Dashboard events      – BotEvent wysyłany do SignalR
//   + Whitelist IP          – zaufane IP nigdy nie dostają bana
//   + YARP path transform   – /proxy/get → /get na backendzie
// =====================================================================

using System.Threading.RateLimiting;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.SignalR;
using Microsoft.Extensions.Caching.Memory;
using Yarp.ReverseProxy.Configuration;
using System.Net;
using System.Collections.Concurrent;
using System.Threading.Channels;
using System.Security.Cryptography;
using System.Text;
using StackExchange.Redis;
using MaxMind.GeoIP2;

var builder = WebApplication.CreateBuilder(args);
var cfg     = builder.Configuration;

TimeSpan banDuration       = cfg.GetValue<TimeSpan?>("BanDuration")        ?? TimeSpan.FromHours(1);
TimeSpan violationDecayTtl = cfg.GetValue<TimeSpan?>("ViolationDecayTtl")  ?? TimeSpan.FromHours(1);
TimeSpan banCacheTtl       = cfg.GetValue<TimeSpan?>("BanCacheTtl")        ?? TimeSpan.FromSeconds(10);
string   redisConn         = cfg.GetValue<string>("Redis:ConnectionString") ?? "localhost:6379";
string   geoDbPath         = cfg.GetValue<string>("GeoIp:DbPath")           ?? "GeoLite2-Country.mmdb";
int      botScoreThreshold = cfg.GetValue<int?>("BotScoreThreshold")        ?? 60;
int      fpViolationLimit  = cfg.GetValue<int?>("FingerprintViolationLimit") ?? 5;

var blockedCountries = cfg.GetSection("GeoIp:BlockedCountries")
                          .Get<HashSet<string>>() ?? new HashSet<string>();

var trustedProxies   = cfg.GetSection("TrustedProxies")
                          .Get<HashSet<string>>() ?? new HashSet<string>();

var whitelistedIps   = cfg.GetSection("WhitelistedIps")
                          .Get<HashSet<string>>() ?? new HashSet<string>();

// ── Redis ─────────────────────────────────────────────────────────────
var redisOpts = ConfigurationOptions.Parse(redisConn);
redisOpts.AbortOnConnectFail = false;
var redis      = await ConnectionMultiplexer.ConnectAsync(redisOpts);
var db         = redis.GetDatabase();
var subscriber = redis.GetSubscriber();

// ── Geo-IP ────────────────────────────────────────────────────────────
DatabaseReader? geoReader = null;
if (File.Exists(geoDbPath))
{
    geoReader = new DatabaseReader(geoDbPath);
    Console.WriteLine($"[GEO-IP] Baza załadowana: {geoDbPath} | Blokowane: {string.Join(", ", blockedCountries)}");
}
else
{
    Console.ForegroundColor = ConsoleColor.Yellow;
    Console.WriteLine($"[GEO-IP] UWAGA: Brak pliku {geoDbPath} – blokowanie krajów wyłączone.");
    Console.ResetColor();
}

// ── Log channel ───────────────────────────────────────────────────────
var logChannel = Channel.CreateBounded<string>(new BoundedChannelOptions(4096)
{
    FullMode = BoundedChannelFullMode.DropOldest
});

var logWriterTask = Task.Run(async () =>
{
    await foreach (var entry in logChannel.Reader.ReadAllAsync())
    {
        try   { await File.AppendAllTextAsync("logs.txt", entry + Environment.NewLine); }
        catch { }
    }
});

// ── Services ──────────────────────────────────────────────────────────
builder.Services.AddSignalR();
builder.Services.AddDirectoryBrowser();
builder.Services.AddMemoryCache();

// POPRAWKA: Transformacja ścieżki – usuwa prefiks /proxy/ przed wysłaniem do backendu
// Przykład: /proxy/get → /get na docelowym serwerze
var routes = new[]
{
    new RouteConfig
    {
        RouteId    = "route1",
        ClusterId  = "cluster1",
        Match      = new RouteMatch { Path = "/proxy/{**catch-all}" },
        Transforms = new List<Dictionary<string, string>>
        {
            new Dictionary<string, string> { { "PathPattern", "/{**catch-all}" } }
        }
    }
};

var clusters = new[]
{
    new ClusterConfig
    {
        ClusterId    = "cluster1",
        Destinations = new Dictionary<string, DestinationConfig>
        {
            // httpbin.org – idealne do testów, zwraca JSON z nagłówkami i IP
            // Zmień na własny backend w produkcji
            { "dest1", new DestinationConfig { Address = "https://httpbin.org" } }
        },
        HttpRequest = new Yarp.ReverseProxy.Forwarder.ForwarderRequestConfig
        {
            ActivityTimeout = TimeSpan.FromSeconds(30)
        }
    }
};

builder.Services.AddReverseProxy().LoadFromMemory(routes, clusters);

builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.AddPolicy("fixed-policy", httpContext =>
    {
        string clientIp = ResolveClientIp(httpContext, trustedProxies);
        if (IPAddress.TryParse(clientIp, out var a) && IPAddress.IsLoopback(a))
            return RateLimitPartition.GetNoLimiter("localhost");

        return RateLimitPartition.GetFixedWindowLimiter(clientIp,
            _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 30,
                Window      = TimeSpan.FromSeconds(10)
            });
    });
});

var app = builder.Build();

// ── Helpers ───────────────────────────────────────────────────────────

static string ResolveClientIp(HttpContext ctx, HashSet<string> trustedProxies)
{
    var remoteIp = ctx.Connection.RemoteIpAddress?.ToString();
    if (remoteIp != null && trustedProxies.Contains(remoteIp))
    {
        var forwarded = ctx.Request.Headers["X-Forwarded-For"].FirstOrDefault();
        if (!string.IsNullOrWhiteSpace(forwarded))
        {
            var first = forwarded.Split(',')[0].Trim();
            if (IPAddress.TryParse(first, out _)) return first;
        }
    }
    return remoteIp ?? "::1";
}

string? ResolveCountry(string ip)
{
    if (geoReader is null) return null;
    if (!IPAddress.TryParse(ip, out var addr) || IPAddress.IsLoopback(addr)) return null;
    try   { return geoReader.Country(ip).Country.IsoCode; }
    catch { return null; }
}

void Logger(string message, ConsoleColor color = ConsoleColor.Gray)
{
    string logEntry = $"[{DateTime.Now:HH:mm:ss}] {message}";
    Console.ForegroundColor = color;
    Console.WriteLine(logEntry);
    Console.ResetColor();
    logChannel.Writer.TryWrite(logEntry);
}

// ── Fingerprinting ────────────────────────────────────────────────────

static string ComputeFingerprint(HttpRequest req)
{
    var ua      = req.Headers["User-Agent"].ToString();
    var al      = req.Headers["Accept-Language"].ToString();
    var ae      = req.Headers["Accept-Encoding"].ToString();
    var acc     = req.Headers["Accept"].ToString();
    var sec     = req.Headers["Sec-Ch-Ua"].ToString();
    var secMob  = req.Headers["Sec-Ch-Ua-Mobile"].ToString();
    var secPlat = req.Headers["Sec-Ch-Ua-Platform"].ToString();
    var order   = string.Join(",", req.Headers.Keys.Take(8));

    var raw  = $"{ua}|{al}|{ae}|{acc}|{sec}|{secMob}|{secPlat}|{order}";
    var hash = SHA256.HashData(Encoding.UTF8.GetBytes(raw));
    return Convert.ToHexString(hash)[..16];
}

static int ComputeBotScore(HttpRequest req)
{
    int score = 0;
    var ua = req.Headers["User-Agent"].ToString();

    if (string.IsNullOrWhiteSpace(ua))
    {
        score += 40;
    }
    else
    {
        string[] botSignatures =
        [
            "curl", "wget", "python-requests", "python-urllib",
            "go-http-client", "java/", "okhttp", "axios",
            "libwww-perl", "scrapy", "bot", "crawler", "spider",
            "headless", "phantomjs", "selenium", "playwright"
        ];
        if (botSignatures.Any(sig => ua.Contains(sig, StringComparison.OrdinalIgnoreCase)))
            score += 35;
    }

    if (string.IsNullOrWhiteSpace(req.Headers["Accept-Language"]))  score += 20;
    if (string.IsNullOrWhiteSpace(req.Headers["Accept-Encoding"]))  score += 15;
    if (string.IsNullOrWhiteSpace(req.Headers["Accept"]))           score += 10;
    if (!string.IsNullOrWhiteSpace(req.Headers["Postman-Token"]))   score += 10;
    if (string.IsNullOrWhiteSpace(req.Headers["Cookie"]))           score += 5;

    return Math.Min(score, 100);
}

// ── Circuit Breaker ───────────────────────────────────────────────────

async Task<bool> IsBannedInRedisAsync(string key)
{
    try   { return (await db.StringGetAsync(key)).HasValue; }
    catch (RedisException ex)
    {
        Logger($"[REDIS] Błąd ban-check {key}: {ex.Message}", ConsoleColor.DarkYellow);
        return false;
    }
}

async Task<int> IncrementAsync(string key)
{
    try
    {
        long count = await db.StringIncrementAsync(key);
        if (count == 1) await db.KeyExpireAsync(key, violationDecayTtl);
        return (int)count;
    }
    catch (RedisException ex)
    {
        Logger($"[REDIS] Błąd increment {key}: {ex.Message}", ConsoleColor.DarkYellow);
        return 0;
    }
}

// ── Event buffer ──────────────────────────────────────────────────────
var eventBuffer = new ConcurrentQueue<object>();

async Task BanIpAsync(string ip, string? country, IMemoryCache banCache)
{
    try
    {
        await db.StringSetAsync($"shieldx:ban:{ip}", "1", banDuration);
        await subscriber.PublishAsync(RedisChannel.Literal("shieldx:bans"), ip);
    }
    catch (RedisException ex)
    {
        Logger($"[REDIS] Błąd zapisu bana IP {ip}: {ex.Message}", ConsoleColor.DarkYellow);
    }

    banCache.Set($"ban:{ip}", true, banDuration);
    Logger($"[!!!] AUTO-BAN IP: {ip} [{country ?? "??"}] → {banDuration.TotalMinutes:0} min",
           ConsoleColor.Red);

    eventBuffer.Enqueue(new
    {
        type     = "ban",
        ip,
        country  = country ?? "??",
        expiry   = DateTimeOffset.UtcNow.Add(banDuration).ToString("HH:mm:ss"),
        duration = (int)banDuration.TotalMinutes
    });
}

async Task BanFingerprintAsync(string fp, string ip, string? country,
                               int score, IMemoryCache banCache)
{
    try
    {
        await db.StringSetAsync($"shieldx:ban:fp:{fp}", ip, banDuration);
        await subscriber.PublishAsync(RedisChannel.Literal("shieldx:bans:fp"), fp);
    }
    catch (RedisException ex)
    {
        Logger($"[REDIS] Błąd zapisu bana FP {fp}: {ex.Message}", ConsoleColor.DarkYellow);
    }

    banCache.Set($"ban:fp:{fp}", true, banDuration);
    Logger($"[!!!] AUTO-BAN FP: {fp} (score={score}) IP={ip} [{country ?? "??"}] → {banDuration.TotalMinutes:0} min",
           ConsoleColor.Magenta);

    eventBuffer.Enqueue(new
    {
        type        = "bot",
        ip,
        fingerprint = fp,
        score,
        country     = country ?? "??",
        expiry      = DateTimeOffset.UtcNow.Add(banDuration).ToString("HH:mm:ss"),
        duration    = (int)banDuration.TotalMinutes
    });
}

// ── Redis Pub/Sub ─────────────────────────────────────────────────────
await subscriber.SubscribeAsync(RedisChannel.Literal("shieldx:bans"), (_, ip) =>
{
    Logger($"[SYNC] Ban IP odebrany od węzła: {ip}", ConsoleColor.Magenta);
    var cache = app.Services.GetRequiredService<IMemoryCache>();
    cache.Set($"ban:{(string)ip!}", true, banDuration);
});

await subscriber.SubscribeAsync(RedisChannel.Literal("shieldx:bans:fp"), (_, fp) =>
{
    Logger($"[SYNC] Ban FP odebrany od węzła: {fp}", ConsoleColor.Magenta);
    var cache = app.Services.GetRequiredService<IMemoryCache>();
    cache.Set($"ban:fp:{(string)fp!}", true, banDuration);
});

// =====================================================================
// PIPELINE
// =====================================================================

app.UseStaticFiles();
app.MapGet("/", () => Results.Redirect("/dashboard.html"));
app.MapHub<ShieldXHub>("/shieldx-hub");

var hubCtx   = app.Services.GetRequiredService<IHubContext<ShieldXHub>>();
var banCache = app.Services.GetRequiredService<IMemoryCache>();

// Flush timer – paczki SignalR co 1 sekundę
var flushTimer = new System.Timers.Timer(1000);
flushTimer.Elapsed += async (_, _) =>
{
    if (eventBuffer.IsEmpty) return;
    var batch = new List<object>();
    while (eventBuffer.TryDequeue(out var ev)) batch.Add(ev);
    try
    {
        foreach (var ev in batch)
        {
            dynamic d    = ev;
            string  type = (string)d.type;
            switch (type)
            {
                case "ban":
                    await hubCtx.Clients.All.SendAsync("BanEvent", ev);
                    break;
                case "violation":
                    await hubCtx.Clients.All.SendAsync("ViolationEvent", ev);
                    break;
                case "geoblock":
                    await hubCtx.Clients.All.SendAsync("GeoBlock", ev);
                    break;
                case "bot":
                    await hubCtx.Clients.All.SendAsync("BotEvent", ev);
                    break;
            }
        }
    }
    catch { }
};
flushTimer.Start();

// ── Middleware antyfrodowy ─────────────────────────────────────────────
app.Use(async (context, next) =>
{
    string clientIp = ResolveClientIp(context, trustedProxies);

    if (IPAddress.TryParse(clientIp, out var addr) && IPAddress.IsLoopback(addr))
    {
        await next();
        return;
    }

    if (whitelistedIps.Contains(clientIp))
    {
        await next();
        return;
    }

    string? country     = ResolveCountry(clientIp);
    string  fingerprint = ComputeFingerprint(context.Request);
    int     botScore    = ComputeBotScore(context.Request);

    // ── 1. Sprawdź ban IP ──────────────────────────────────────────────
    if (!banCache.TryGetValue($"ban:{clientIp}", out _))
    {
        if (await IsBannedInRedisAsync($"shieldx:ban:{clientIp}"))
            banCache.Set($"ban:{clientIp}", true, banCacheTtl);
    }

    if (banCache.TryGetValue($"ban:{clientIp}", out _))
    {
        var ttl  = await db.KeyTimeToLiveAsync($"shieldx:ban:{clientIp}");
        double m = ttl?.TotalMinutes ?? 0;
        context.Response.StatusCode = 403;
        await context.Response.WriteAsync($"IP ZABLOKOWANE. Ban wygasa za {m:0.0} minut.");
        return;
    }

    // ── 2. Sprawdź ban fingerprint ────────────────────────────────────
    if (!banCache.TryGetValue($"ban:fp:{fingerprint}", out _))
    {
        if (await IsBannedInRedisAsync($"shieldx:ban:fp:{fingerprint}"))
            banCache.Set($"ban:fp:{fingerprint}", true, banCacheTtl);
    }

    if (banCache.TryGetValue($"ban:fp:{fingerprint}", out _))
    {
        Logger($"[BOT-BAN] FP={fingerprint} IP={clientIp} [{country ?? "??"}] zablokowany",
               ConsoleColor.Magenta);
        context.Response.StatusCode = 403;
        await context.Response.WriteAsync("Zablokowano – wykryto automatyczny klient.");
        return;
    }

    // ── 3. Sprawdź Geo-IP ─────────────────────────────────────────────
    if (country is not null && blockedCountries.Contains(country))
    {
        context.Response.StatusCode = 403;
        Logger($"[GEO] Zablokowano {clientIp} [{country}]", ConsoleColor.DarkRed);
        await context.Response.WriteAsync($"Dostęp zablokowany dla regionu: {country}");
        eventBuffer.Enqueue(new { type = "geoblock", ip = clientIp, country });
        return;
    }

    // ── 4. Ocena Bot Score ────────────────────────────────────────────
    if (botScore >= botScoreThreshold)
    {
        int fpViolations = await IncrementAsync($"shieldx:violations:fp:{fingerprint}");

        Logger($"[BOT] Score={botScore} FP={fingerprint} IP={clientIp} [{country ?? "??"}] " +
               $"Naruszenia: {fpViolations}/{fpViolationLimit}",
               ConsoleColor.DarkMagenta);

        eventBuffer.Enqueue(new
        {
            type        = "bot",
            ip          = clientIp,
            fingerprint,
            score       = botScore,
            country     = country ?? "??",
            violations  = fpViolations,
            threshold   = fpViolationLimit,
            expiry      = "",
            duration    = 0
        });

        if (fpViolations >= fpViolationLimit)
        {
            await BanFingerprintAsync(fingerprint, clientIp, country, botScore, banCache);
            if (botScore >= 80)
                await BanIpAsync(clientIp, country, banCache);
        }

        context.Response.StatusCode = 403;
        await context.Response.WriteAsync("Zablokowano – wykryto automatyczny klient.");
        return;
    }

    await next();

    // ── 5. Obsługa 429 (rate limit) ───────────────────────────────────
    if (context.Response.StatusCode == 429)
    {
        int violations = await IncrementAsync($"shieldx:violations:{clientIp}");
        Logger($"[!] OSTRZEZENIE: {clientIp} [{country ?? "??"}] (Przewinienie: {violations}/3)",
               ConsoleColor.Yellow);

        eventBuffer.Enqueue(new
        {
            type      = "violation",
            ip        = clientIp,
            country   = country ?? "??",
            count     = violations,
            threshold = 3
        });

        if (violations == 3)
            await BanIpAsync(clientIp, country, banCache);
    }
});

app.UseRateLimiter();

app.MapReverseProxy(proxy =>
{
    proxy.Use(async (context, next) =>
    {
        var ip = ResolveClientIp(context, trustedProxies);
        Logger(
            $"[OK] {context.Request.Method} {context.Request.Path} " +
            $"od {ip} [{ResolveCountry(ip) ?? "??"}]",
            ConsoleColor.Green);
        await next();
    });
}).RequireRateLimiting("fixed-policy");

// ── Graceful shutdown ─────────────────────────────────────────────────
var lifetime = app.Services.GetRequiredService<IHostApplicationLifetime>();
lifetime.ApplicationStopping.Register(() =>
{
    flushTimer.Stop();
    flushTimer.Dispose();
    logChannel.Writer.Complete();
    logWriterTask.Wait(TimeSpan.FromSeconds(5));
    geoReader?.Dispose();
    redis.Dispose();
});

Logger("=== SHIELD-X V7 [GLOBAL SCALE + FINGERPRINTING] URUCHOMIONY ===", ConsoleColor.Cyan);
Logger($"    Redis              : {redisConn}",                                                                    ConsoleColor.Cyan);
Logger($"    Ban TTL            : {banDuration.TotalMinutes:0} min",                                              ConsoleColor.Cyan);
Logger($"    Ban cache TTL      : {banCacheTtl.TotalSeconds:0} s",                                                ConsoleColor.Cyan);
Logger($"    Violation TTL      : {violationDecayTtl.TotalMinutes:0} min",                                        ConsoleColor.Cyan);
Logger($"    Bot score threshold: {botScoreThreshold}/100",                                                        ConsoleColor.Cyan);
Logger($"    FP violation limit : {fpViolationLimit}",                                                            ConsoleColor.Cyan);
Logger($"    Trusted proxies    : {(trustedProxies.Count > 0 ? string.Join(", ", trustedProxies) : "brak")}",    ConsoleColor.Cyan);
Logger($"    Whitelisted IPs    : {(whitelistedIps.Count > 0 ? string.Join(", ", whitelistedIps) : "brak")}",    ConsoleColor.Cyan);
Logger($"    Geo-IP             : {(geoReader is not null ? $"aktywny ({blockedCountries.Count} krajów)" : "wyłączony")}", ConsoleColor.Cyan);
Logger($"    Proxy cel          : httpbin.org (zmień w kodzie na własny backend)",                                ConsoleColor.Cyan);
Logger($"    Dashboard          : http://localhost:5000/dashboard.html",                                           ConsoleColor.Cyan);
app.Run();

// ── SignalR Hub ───────────────────────────────────────────────────────
public class ShieldXHub : Hub
{
    public async Task RequestStats()
    {
        await Clients.Caller.SendAsync("StatsResponse", new
        {
            timestamp = DateTime.UtcNow.ToString("o"),
            message   = "Połączono z Shield-X V7 [FINGERPRINTING]"
        });
    }
}
// =====================================================================
// SHIELD-X V7 – "Global Scale" Edition + Browser Fingerprinting
// =====================================================================
// Zmiany względem poprzedniej wersji:
//   + ComputeFingerprint()  – hash SHA-256 z nagłówków HTTP
//   + BotScore()            – punktacja podejrzanych sygnałów (0-100)
//   + Bany per fingerprint  – Redis: shieldx:ban:fp:{hash}
//   + Violations per fp     – Redis: shieldx:violations:fp:{hash}
//   + Dashboard events      – BotEvent wysyłany do SignalR
//   + Whitelist IP          – zaufane IP nigdy nie dostają bana
//   + YARP path transform   – /proxy/get → /get na backendzie
// =====================================================================

using System.Threading.RateLimiting;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.SignalR;
using Microsoft.Extensions.Caching.Memory;
using Yarp.ReverseProxy.Configuration;
using System.Net;
using System.Collections.Concurrent;
using System.Threading.Channels;
using System.Security.Cryptography;
using System.Text;
using StackExchange.Redis;
using MaxMind.GeoIP2;

var builder = WebApplication.CreateBuilder(args);
var cfg     = builder.Configuration;

TimeSpan banDuration       = cfg.GetValue<TimeSpan?>("BanDuration")        ?? TimeSpan.FromHours(1);
TimeSpan violationDecayTtl = cfg.GetValue<TimeSpan?>("ViolationDecayTtl")  ?? TimeSpan.FromHours(1);
TimeSpan banCacheTtl       = cfg.GetValue<TimeSpan?>("BanCacheTtl")        ?? TimeSpan.FromSeconds(10);
string   redisConn         = cfg.GetValue<string>("Redis:ConnectionString") ?? "localhost:6379";
string   geoDbPath         = cfg.GetValue<string>("GeoIp:DbPath")           ?? "GeoLite2-Country.mmdb";
int      botScoreThreshold = cfg.GetValue<int?>("BotScoreThreshold")        ?? 60;
int      fpViolationLimit  = cfg.GetValue<int?>("FingerprintViolationLimit") ?? 5;

var blockedCountries = cfg.GetSection("GeoIp:BlockedCountries")
                          .Get<HashSet<string>>() ?? new HashSet<string>();

var trustedProxies   = cfg.GetSection("TrustedProxies")
                          .Get<HashSet<string>>() ?? new HashSet<string>();

var whitelistedIps   = cfg.GetSection("WhitelistedIps")
                          .Get<HashSet<string>>() ?? new HashSet<string>();

// ── Redis ─────────────────────────────────────────────────────────────
var redisOpts = ConfigurationOptions.Parse(redisConn);
redisOpts.AbortOnConnectFail = false;
var redis      = await ConnectionMultiplexer.ConnectAsync(redisOpts);
var db         = redis.GetDatabase();
var subscriber = redis.GetSubscriber();

// ── Geo-IP ────────────────────────────────────────────────────────────
DatabaseReader? geoReader = null;
if (File.Exists(geoDbPath))
{
    geoReader = new DatabaseReader(geoDbPath);
    Console.WriteLine($"[GEO-IP] Baza załadowana: {geoDbPath} | Blokowane: {string.Join(", ", blockedCountries)}");
}
else
{
    Console.ForegroundColor = ConsoleColor.Yellow;
    Console.WriteLine($"[GEO-IP] UWAGA: Brak pliku {geoDbPath} – blokowanie krajów wyłączone.");
    Console.ResetColor();
}

// ── Log channel ───────────────────────────────────────────────────────
var logChannel = Channel.CreateBounded<string>(new BoundedChannelOptions(4096)
{
    FullMode = BoundedChannelFullMode.DropOldest
});

var logWriterTask = Task.Run(async () =>
{
    await foreach (var entry in logChannel.Reader.ReadAllAsync())
    {
        try   { await File.AppendAllTextAsync("logs.txt", entry + Environment.NewLine); }
        catch { }
    }
});

// ── Services ──────────────────────────────────────────────────────────
builder.Services.AddSignalR();
builder.Services.AddDirectoryBrowser();
builder.Services.AddMemoryCache();

// POPRAWKA: Transformacja ścieżki – usuwa prefiks /proxy/ przed wysłaniem do backendu
// Przykład: /proxy/get → /get na docelowym serwerze
var routes = new[]
{
    new RouteConfig
    {
        RouteId    = "route1",
        ClusterId  = "cluster1",
        Match      = new RouteMatch { Path = "/proxy/{**catch-all}" },
        Transforms = new List<Dictionary<string, string>>
        {
            new Dictionary<string, string> { { "PathPattern", "/{**catch-all}" } }
        }
    }
};

var clusters = new[]
{
    new ClusterConfig
    {
        ClusterId    = "cluster1",
        Destinations = new Dictionary<string, DestinationConfig>
        {
            // httpbin.org – idealne do testów, zwraca JSON z nagłówkami i IP
            // Zmień na własny backend w produkcji
            { "dest1", new DestinationConfig { Address = "https://httpbin.org" } }
        },
        HttpRequest = new Yarp.ReverseProxy.Forwarder.ForwarderRequestConfig
        {
            ActivityTimeout = TimeSpan.FromSeconds(30)
        }
    }
};

builder.Services.AddReverseProxy().LoadFromMemory(routes, clusters);

builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.AddPolicy("fixed-policy", httpContext =>
    {
        string clientIp = ResolveClientIp(httpContext, trustedProxies);
        if (IPAddress.TryParse(clientIp, out var a) && IPAddress.IsLoopback(a))
            return RateLimitPartition.GetNoLimiter("localhost");

        return RateLimitPartition.GetFixedWindowLimiter(clientIp,
            _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 30,
                Window      = TimeSpan.FromSeconds(10)
            });
    });
});

var app = builder.Build();

// ── Helpers ───────────────────────────────────────────────────────────

static string ResolveClientIp(HttpContext ctx, HashSet<string> trustedProxies)
{
    var remoteIp = ctx.Connection.RemoteIpAddress?.ToString();
    if (remoteIp != null && trustedProxies.Contains(remoteIp))
    {
        var forwarded = ctx.Request.Headers["X-Forwarded-For"].FirstOrDefault();
        if (!string.IsNullOrWhiteSpace(forwarded))
        {
            var first = forwarded.Split(',')[0].Trim();
            if (IPAddress.TryParse(first, out _)) return first;
        }
    }
    return remoteIp ?? "::1";
}

string? ResolveCountry(string ip)
{
    if (geoReader is null) return null;
    if (!IPAddress.TryParse(ip, out var addr) || IPAddress.IsLoopback(addr)) return null;
    try   { return geoReader.Country(ip).Country.IsoCode; }
    catch { return null; }
}

void Logger(string message, ConsoleColor color = ConsoleColor.Gray)
{
    string logEntry = $"[{DateTime.Now:HH:mm:ss}] {message}";
    Console.ForegroundColor = color;
    Console.WriteLine(logEntry);
    Console.ResetColor();
    logChannel.Writer.TryWrite(logEntry);
}

// ── Fingerprinting ────────────────────────────────────────────────────

static string ComputeFingerprint(HttpRequest req)
{
    var ua      = req.Headers["User-Agent"].ToString();
    var al      = req.Headers["Accept-Language"].ToString();
    var ae      = req.Headers["Accept-Encoding"].ToString();
    var acc     = req.Headers["Accept"].ToString();
    var sec     = req.Headers["Sec-Ch-Ua"].ToString();
    var secMob  = req.Headers["Sec-Ch-Ua-Mobile"].ToString();
    var secPlat = req.Headers["Sec-Ch-Ua-Platform"].ToString();
    var order   = string.Join(",", req.Headers.Keys.Take(8));

    var raw  = $"{ua}|{al}|{ae}|{acc}|{sec}|{secMob}|{secPlat}|{order}";
    var hash = SHA256.HashData(Encoding.UTF8.GetBytes(raw));
    return Convert.ToHexString(hash)[..16];
}

static int ComputeBotScore(HttpRequest req)
{
    int score = 0;
    var ua = req.Headers["User-Agent"].ToString();

    if (string.IsNullOrWhiteSpace(ua))
    {
        score += 40;
    }
    else
    {
        string[] botSignatures =
        [
            "curl", "wget", "python-requests", "python-urllib",
            "go-http-client", "java/", "okhttp", "axios",
            "libwww-perl", "scrapy", "bot", "crawler", "spider",
            "headless", "phantomjs", "selenium", "playwright"
        ];
        if (botSignatures.Any(sig => ua.Contains(sig, StringComparison.OrdinalIgnoreCase)))
            score += 35;
    }

    if (string.IsNullOrWhiteSpace(req.Headers["Accept-Language"]))  score += 20;
    if (string.IsNullOrWhiteSpace(req.Headers["Accept-Encoding"]))  score += 15;
    if (string.IsNullOrWhiteSpace(req.Headers["Accept"]))           score += 10;
    if (!string.IsNullOrWhiteSpace(req.Headers["Postman-Token"]))   score += 10;
    if (string.IsNullOrWhiteSpace(req.Headers["Cookie"]))           score += 5;

    return Math.Min(score, 100);
}

// ── Circuit Breaker ───────────────────────────────────────────────────

async Task<bool> IsBannedInRedisAsync(string key)
{
    try   { return (await db.StringGetAsync(key)).HasValue; }
    catch (RedisException ex)
    {
        Logger($"[REDIS] Błąd ban-check {key}: {ex.Message}", ConsoleColor.DarkYellow);
        return false;
    }
}

async Task<int> IncrementAsync(string key)
{
    try
    {
        long count = await db.StringIncrementAsync(key);
        if (count == 1) await db.KeyExpireAsync(key, violationDecayTtl);
        return (int)count;
    }
    catch (RedisException ex)
    {
        Logger($"[REDIS] Błąd increment {key}: {ex.Message}", ConsoleColor.DarkYellow);
        return 0;
    }
}

// ── Event buffer ──────────────────────────────────────────────────────
var eventBuffer = new ConcurrentQueue<object>();

async Task BanIpAsync(string ip, string? country, IMemoryCache banCache)
{
    try
    {
        await db.StringSetAsync($"shieldx:ban:{ip}", "1", banDuration);
        await subscriber.PublishAsync(RedisChannel.Literal("shieldx:bans"), ip);
    }
    catch (RedisException ex)
    {
        Logger($"[REDIS] Błąd zapisu bana IP {ip}: {ex.Message}", ConsoleColor.DarkYellow);
    }

    banCache.Set($"ban:{ip}", true, banDuration);
    Logger($"[!!!] AUTO-BAN IP: {ip} [{country ?? "??"}] → {banDuration.TotalMinutes:0} min",
           ConsoleColor.Red);

    eventBuffer.Enqueue(new
    {
        type     = "ban",
        ip,
        country  = country ?? "??",
        expiry   = DateTimeOffset.UtcNow.Add(banDuration).ToString("HH:mm:ss"),
        duration = (int)banDuration.TotalMinutes
    });
}

async Task BanFingerprintAsync(string fp, string ip, string? country,
                               int score, IMemoryCache banCache)
{
    try
    {
        await db.StringSetAsync($"shieldx:ban:fp:{fp}", ip, banDuration);
        await subscriber.PublishAsync(RedisChannel.Literal("shieldx:bans:fp"), fp);
    }
    catch (RedisException ex)
    {
        Logger($"[REDIS] Błąd zapisu bana FP {fp}: {ex.Message}", ConsoleColor.DarkYellow);
    }

    banCache.Set($"ban:fp:{fp}", true, banDuration);
    Logger($"[!!!] AUTO-BAN FP: {fp} (score={score}) IP={ip} [{country ?? "??"}] → {banDuration.TotalMinutes:0} min",
           ConsoleColor.Magenta);

    eventBuffer.Enqueue(new
    {
        type        = "bot",
        ip,
        fingerprint = fp,
        score,
        country     = country ?? "??",
        expiry      = DateTimeOffset.UtcNow.Add(banDuration).ToString("HH:mm:ss"),
        duration    = (int)banDuration.TotalMinutes
    });
}

// ── Redis Pub/Sub ─────────────────────────────────────────────────────
await subscriber.SubscribeAsync(RedisChannel.Literal("shieldx:bans"), (_, ip) =>
{
    Logger($"[SYNC] Ban IP odebrany od węzła: {ip}", ConsoleColor.Magenta);
    var cache = app.Services.GetRequiredService<IMemoryCache>();
    cache.Set($"ban:{(string)ip!}", true, banDuration);
});

await subscriber.SubscribeAsync(RedisChannel.Literal("shieldx:bans:fp"), (_, fp) =>
{
    Logger($"[SYNC] Ban FP odebrany od węzła: {fp}", ConsoleColor.Magenta);
    var cache = app.Services.GetRequiredService<IMemoryCache>();
    cache.Set($"ban:fp:{(string)fp!}", true, banDuration);
});

// =====================================================================
// PIPELINE
// =====================================================================

app.UseStaticFiles();
app.MapGet("/", () => Results.Redirect("/dashboard.html"));
app.MapHub<ShieldXHub>("/shieldx-hub");

var hubCtx   = app.Services.GetRequiredService<IHubContext<ShieldXHub>>();
var banCache = app.Services.GetRequiredService<IMemoryCache>();

// Flush timer – paczki SignalR co 1 sekundę
var flushTimer = new System.Timers.Timer(1000);
flushTimer.Elapsed += async (_, _) =>
{
    if (eventBuffer.IsEmpty) return;
    var batch = new List<object>();
    while (eventBuffer.TryDequeue(out var ev)) batch.Add(ev);
    try
    {
        foreach (var ev in batch)
        {
            dynamic d    = ev;
            string  type = (string)d.type;
            switch (type)
            {
                case "ban":
                    await hubCtx.Clients.All.SendAsync("BanEvent", ev);
                    break;
                case "violation":
                    await hubCtx.Clients.All.SendAsync("ViolationEvent", ev);
                    break;
                case "geoblock":
                    await hubCtx.Clients.All.SendAsync("GeoBlock", ev);
                    break;
                case "bot":
                    await hubCtx.Clients.All.SendAsync("BotEvent", ev);
                    break;
            }
        }
    }
    catch { }
};
flushTimer.Start();

// ── Middleware antyfrodowy ─────────────────────────────────────────────
app.Use(async (context, next) =>
{
    string clientIp = ResolveClientIp(context, trustedProxies);

    if (IPAddress.TryParse(clientIp, out var addr) && IPAddress.IsLoopback(addr))
    {
        await next();
        return;
    }

    if (whitelistedIps.Contains(clientIp))
    {
        await next();
        return;
    }

    string? country     = ResolveCountry(clientIp);
    string  fingerprint = ComputeFingerprint(context.Request);
    int     botScore    = ComputeBotScore(context.Request);

    // ── 1. Sprawdź ban IP ──────────────────────────────────────────────
    if (!banCache.TryGetValue($"ban:{clientIp}", out _))
    {
        if (await IsBannedInRedisAsync($"shieldx:ban:{clientIp}"))
            banCache.Set($"ban:{clientIp}", true, banCacheTtl);
    }

    if (banCache.TryGetValue($"ban:{clientIp}", out _))
    {
        var ttl  = await db.KeyTimeToLiveAsync($"shieldx:ban:{clientIp}");
        double m = ttl?.TotalMinutes ?? 0;
        context.Response.StatusCode = 403;
        await context.Response.WriteAsync($"IP ZABLOKOWANE. Ban wygasa za {m:0.0} minut.");
        return;
    }

    // ── 2. Sprawdź ban fingerprint ────────────────────────────────────
    if (!banCache.TryGetValue($"ban:fp:{fingerprint}", out _))
    {
        if (await IsBannedInRedisAsync($"shieldx:ban:fp:{fingerprint}"))
            banCache.Set($"ban:fp:{fingerprint}", true, banCacheTtl);
    }

    if (banCache.TryGetValue($"ban:fp:{fingerprint}", out _))
    {
        Logger($"[BOT-BAN] FP={fingerprint} IP={clientIp} [{country ?? "??"}] zablokowany",
               ConsoleColor.Magenta);
        context.Response.StatusCode = 403;
        await context.Response.WriteAsync("Zablokowano – wykryto automatyczny klient.");
        return;
    }

    // ── 3. Sprawdź Geo-IP ─────────────────────────────────────────────
    if (country is not null && blockedCountries.Contains(country))
    {
        context.Response.StatusCode = 403;
        Logger($"[GEO] Zablokowano {clientIp} [{country}]", ConsoleColor.DarkRed);
        await context.Response.WriteAsync($"Dostęp zablokowany dla regionu: {country}");
        eventBuffer.Enqueue(new { type = "geoblock", ip = clientIp, country });
        return;
    }

    // ── 4. Ocena Bot Score ────────────────────────────────────────────
    if (botScore >= botScoreThreshold)
    {
        int fpViolations = await IncrementAsync($"shieldx:violations:fp:{fingerprint}");

        Logger($"[BOT] Score={botScore} FP={fingerprint} IP={clientIp} [{country ?? "??"}] " +
               $"Naruszenia: {fpViolations}/{fpViolationLimit}",
               ConsoleColor.DarkMagenta);

        eventBuffer.Enqueue(new
        {
            type        = "bot",
            ip          = clientIp,
            fingerprint,
            score       = botScore,
            country     = country ?? "??",
            violations  = fpViolations,
            threshold   = fpViolationLimit,
            expiry      = "",
            duration    = 0
        });

        if (fpViolations >= fpViolationLimit)
        {
            await BanFingerprintAsync(fingerprint, clientIp, country, botScore, banCache);
            if (botScore >= 80)
                await BanIpAsync(clientIp, country, banCache);
        }

        context.Response.StatusCode = 403;
        await context.Response.WriteAsync("Zablokowano – wykryto automatyczny klient.");
        return;
    }

    await next();

    // ── 5. Obsługa 429 (rate limit) ───────────────────────────────────
    if (context.Response.StatusCode == 429)
    {
        int violations = await IncrementAsync($"shieldx:violations:{clientIp}");
        Logger($"[!] OSTRZEZENIE: {clientIp} [{country ?? "??"}] (Przewinienie: {violations}/3)",
               ConsoleColor.Yellow);

        eventBuffer.Enqueue(new
        {
            type      = "violation",
            ip        = clientIp,
            country   = country ?? "??",
            count     = violations,
            threshold = 3
        });

        if (violations == 3)
            await BanIpAsync(clientIp, country, banCache);
    }
});

app.UseRateLimiter();

app.MapReverseProxy(proxy =>
{
    proxy.Use(async (context, next) =>
    {
        var ip = ResolveClientIp(context, trustedProxies);
        Logger(
            $"[OK] {context.Request.Method} {context.Request.Path} " +
            $"od {ip} [{ResolveCountry(ip) ?? "??"}]",
            ConsoleColor.Green);
        await next();
    });
}).RequireRateLimiting("fixed-policy");

// ── Graceful shutdown ─────────────────────────────────────────────────
var lifetime = app.Services.GetRequiredService<IHostApplicationLifetime>();
lifetime.ApplicationStopping.Register(() =>
{
    flushTimer.Stop();
    flushTimer.Dispose();
    logChannel.Writer.Complete();
    logWriterTask.Wait(TimeSpan.FromSeconds(5));
    geoReader?.Dispose();
    redis.Dispose();
});

Logger("=== SHIELD-X V7 [GLOBAL SCALE + FINGERPRINTING] URUCHOMIONY ===", ConsoleColor.Cyan);
Logger($"    Redis              : {redisConn}",                                                                    ConsoleColor.Cyan);
Logger($"    Ban TTL            : {banDuration.TotalMinutes:0} min",                                              ConsoleColor.Cyan);
Logger($"    Ban cache TTL      : {banCacheTtl.TotalSeconds:0} s",                                                ConsoleColor.Cyan);
Logger($"    Violation TTL      : {violationDecayTtl.TotalMinutes:0} min",                                        ConsoleColor.Cyan);
Logger($"    Bot score threshold: {botScoreThreshold}/100",                                                        ConsoleColor.Cyan);
Logger($"    FP violation limit : {fpViolationLimit}",                                                            ConsoleColor.Cyan);
Logger($"    Trusted proxies    : {(trustedProxies.Count > 0 ? string.Join(", ", trustedProxies) : "brak")}",    ConsoleColor.Cyan);
Logger($"    Whitelisted IPs    : {(whitelistedIps.Count > 0 ? string.Join(", ", whitelistedIps) : "brak")}",    ConsoleColor.Cyan);
Logger($"    Geo-IP             : {(geoReader is not null ? $"aktywny ({blockedCountries.Count} krajów)" : "wyłączony")}", ConsoleColor.Cyan);
Logger($"    Proxy cel          : httpbin.org (zmień w kodzie na własny backend)",                                ConsoleColor.Cyan);
Logger($"    Dashboard          : http://localhost:5000/dashboard.html",                                           ConsoleColor.Cyan);
app.Run();

// ── SignalR Hub ───────────────────────────────────────────────────────
public class ShieldXHub : Hub
{
    public async Task RequestStats()
    {
        await Clients.Caller.SendAsync("StatsResponse", new
        {
            timestamp = DateTime.UtcNow.ToString("o"),
            message   = "Połączono z Shield-X V7 [FINGERPRINTING]"
        });
    }
}
// =====================================================================
// SHIELD-X V7 – "Global Scale" Edition + Browser Fingerprinting
// =====================================================================
// Zmiany względem poprzedniej wersji:
//   + ComputeFingerprint()  – hash SHA-256 z nagłówków HTTP
//   + BotScore()            – punktacja podejrzanych sygnałów (0-100)
//   + Bany per fingerprint  – Redis: shieldx:ban:fp:{hash}
//   + Violations per fp     – Redis: shieldx:violations:fp:{hash}
//   + Dashboard events      – BotEvent wysyłany do SignalR
//   + Whitelist IP          – zaufane IP nigdy nie dostają bana
//   + YARP path transform   – /proxy/get → /get na backendzie
// =====================================================================

using System.Threading.RateLimiting;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.SignalR;
using Microsoft.Extensions.Caching.Memory;
using Yarp.ReverseProxy.Configuration;
using System.Net;
using System.Collections.Concurrent;
using System.Threading.Channels;
using System.Security.Cryptography;
using System.Text;
using StackExchange.Redis;
using MaxMind.GeoIP2;

var builder = WebApplication.CreateBuilder(args);
var cfg     = builder.Configuration;

TimeSpan banDuration       = cfg.GetValue<TimeSpan?>("BanDuration")        ?? TimeSpan.FromHours(1);
TimeSpan violationDecayTtl = cfg.GetValue<TimeSpan?>("ViolationDecayTtl")  ?? TimeSpan.FromHours(1);
TimeSpan banCacheTtl       = cfg.GetValue<TimeSpan?>("BanCacheTtl")        ?? TimeSpan.FromSeconds(10);
string   redisConn         = cfg.GetValue<string>("Redis:ConnectionString") ?? "localhost:6379";
string   geoDbPath         = cfg.GetValue<string>("GeoIp:DbPath")           ?? "GeoLite2-Country.mmdb";
int      botScoreThreshold = cfg.GetValue<int?>("BotScoreThreshold")        ?? 60;
int      fpViolationLimit  = cfg.GetValue<int?>("FingerprintViolationLimit") ?? 5;

var blockedCountries = cfg.GetSection("GeoIp:BlockedCountries")
                          .Get<HashSet<string>>() ?? new HashSet<string>();

var trustedProxies   = cfg.GetSection("TrustedProxies")
                          .Get<HashSet<string>>() ?? new HashSet<string>();

var whitelistedIps   = cfg.GetSection("WhitelistedIps")
                          .Get<HashSet<string>>() ?? new HashSet<string>();

// ── Redis ─────────────────────────────────────────────────────────────
var redisOpts = ConfigurationOptions.Parse(redisConn);
redisOpts.AbortOnConnectFail = false;
var redis      = await ConnectionMultiplexer.ConnectAsync(redisOpts);
var db         = redis.GetDatabase();
var subscriber = redis.GetSubscriber();

// ── Geo-IP ────────────────────────────────────────────────────────────
DatabaseReader? geoReader = null;
if (File.Exists(geoDbPath))
{
    geoReader = new DatabaseReader(geoDbPath);
    Console.WriteLine($"[GEO-IP] Baza załadowana: {geoDbPath} | Blokowane: {string.Join(", ", blockedCountries)}");
}
else
{
    Console.ForegroundColor = ConsoleColor.Yellow;
    Console.WriteLine($"[GEO-IP] UWAGA: Brak pliku {geoDbPath} – blokowanie krajów wyłączone.");
    Console.ResetColor();
}

// ── Log channel ───────────────────────────────────────────────────────
var logChannel = Channel.CreateBounded<string>(new BoundedChannelOptions(4096)
{
    FullMode = BoundedChannelFullMode.DropOldest
});

var logWriterTask = Task.Run(async () =>
{
    await foreach (var entry in logChannel.Reader.ReadAllAsync())
    {
        try   { await File.AppendAllTextAsync("logs.txt", entry + Environment.NewLine); }
        catch { }
    }
});

// ── Services ──────────────────────────────────────────────────────────
builder.Services.AddSignalR();
builder.Services.AddDirectoryBrowser();
builder.Services.AddMemoryCache();

// POPRAWKA: Transformacja ścieżki – usuwa prefiks /proxy/ przed wysłaniem do backendu
// Przykład: /proxy/get → /get na docelowym serwerze
var routes = new[]
{
    new RouteConfig
    {
        RouteId    = "route1",
        ClusterId  = "cluster1",
        Match      = new RouteMatch { Path = "/proxy/{**catch-all}" },
        Transforms = new List<Dictionary<string, string>>
        {
            new Dictionary<string, string> { { "PathPattern", "/{**catch-all}" } }
        }
    }
};

var clusters = new[]
{
    new ClusterConfig
    {
        ClusterId    = "cluster1",
        Destinations = new Dictionary<string, DestinationConfig>
        {
            // httpbin.org – idealne do testów, zwraca JSON z nagłówkami i IP
            // Zmień na własny backend w produkcji
            { "dest1", new DestinationConfig { Address = "https://httpbin.org" } }
        },
        HttpRequest = new Yarp.ReverseProxy.Forwarder.ForwarderRequestConfig
        {
            ActivityTimeout = TimeSpan.FromSeconds(30)
        }
    }
};

builder.Services.AddReverseProxy().LoadFromMemory(routes, clusters);

builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.AddPolicy("fixed-policy", httpContext =>
    {
        string clientIp = ResolveClientIp(httpContext, trustedProxies);
        if (IPAddress.TryParse(clientIp, out var a) && IPAddress.IsLoopback(a))
            return RateLimitPartition.GetNoLimiter("localhost");

        return RateLimitPartition.GetFixedWindowLimiter(clientIp,
            _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 30,
                Window      = TimeSpan.FromSeconds(10)
            });
    });
});

var app = builder.Build();

// ── Helpers ───────────────────────────────────────────────────────────

static string ResolveClientIp(HttpContext ctx, HashSet<string> trustedProxies)
{
    var remoteIp = ctx.Connection.RemoteIpAddress?.ToString();
    if (remoteIp != null && trustedProxies.Contains(remoteIp))
    {
        var forwarded = ctx.Request.Headers["X-Forwarded-For"].FirstOrDefault();
        if (!string.IsNullOrWhiteSpace(forwarded))
        {
            var first = forwarded.Split(',')[0].Trim();
            if (IPAddress.TryParse(first, out _)) return first;
        }
    }
    return remoteIp ?? "::1";
}

string? ResolveCountry(string ip)
{
    if (geoReader is null) return null;
    if (!IPAddress.TryParse(ip, out var addr) || IPAddress.IsLoopback(addr)) return null;
    try   { return geoReader.Country(ip).Country.IsoCode; }
    catch { return null; }
}

void Logger(string message, ConsoleColor color = ConsoleColor.Gray)
{
    string logEntry = $"[{DateTime.Now:HH:mm:ss}] {message}";
    Console.ForegroundColor = color;
    Console.WriteLine(logEntry);
    Console.ResetColor();
    logChannel.Writer.TryWrite(logEntry);
}

// ── Fingerprinting ────────────────────────────────────────────────────

static string ComputeFingerprint(HttpRequest req)
{
    var ua      = req.Headers["User-Agent"].ToString();
    var al      = req.Headers["Accept-Language"].ToString();
    var ae      = req.Headers["Accept-Encoding"].ToString();
    var acc     = req.Headers["Accept"].ToString();
    var sec     = req.Headers["Sec-Ch-Ua"].ToString();
    var secMob  = req.Headers["Sec-Ch-Ua-Mobile"].ToString();
    var secPlat = req.Headers["Sec-Ch-Ua-Platform"].ToString();
    var order   = string.Join(",", req.Headers.Keys.Take(8));

    var raw  = $"{ua}|{al}|{ae}|{acc}|{sec}|{secMob}|{secPlat}|{order}";
    var hash = SHA256.HashData(Encoding.UTF8.GetBytes(raw));
    return Convert.ToHexString(hash)[..16];
}

static int ComputeBotScore(HttpRequest req)
{
    int score = 0;
    var ua = req.Headers["User-Agent"].ToString();

    if (string.IsNullOrWhiteSpace(ua))
    {
        score += 40;
    }
    else
    {
        string[] botSignatures =
        [
            "curl", "wget", "python-requests", "python-urllib",
            "go-http-client", "java/", "okhttp", "axios",
            "libwww-perl", "scrapy", "bot", "crawler", "spider",
            "headless", "phantomjs", "selenium", "playwright"
        ];
        if (botSignatures.Any(sig => ua.Contains(sig, StringComparison.OrdinalIgnoreCase)))
            score += 35;
    }

    if (string.IsNullOrWhiteSpace(req.Headers["Accept-Language"]))  score += 20;
    if (string.IsNullOrWhiteSpace(req.Headers["Accept-Encoding"]))  score += 15;
    if (string.IsNullOrWhiteSpace(req.Headers["Accept"]))           score += 10;
    if (!string.IsNullOrWhiteSpace(req.Headers["Postman-Token"]))   score += 10;
    if (string.IsNullOrWhiteSpace(req.Headers["Cookie"]))           score += 5;

    return Math.Min(score, 100);
}

// ── Circuit Breaker ───────────────────────────────────────────────────

async Task<bool> IsBannedInRedisAsync(string key)
{
    try   { return (await db.StringGetAsync(key)).HasValue; }
    catch (RedisException ex)
    {
        Logger($"[REDIS] Błąd ban-check {key}: {ex.Message}", ConsoleColor.DarkYellow);
        return false;
    }
}

async Task<int> IncrementAsync(string key)
{
    try
    {
        long count = await db.StringIncrementAsync(key);
        if (count == 1) await db.KeyExpireAsync(key, violationDecayTtl);
        return (int)count;
    }
    catch (RedisException ex)
    {
        Logger($"[REDIS] Błąd increment {key}: {ex.Message}", ConsoleColor.DarkYellow);
        return 0;
    }
}

// ── Event buffer ──────────────────────────────────────────────────────
var eventBuffer = new ConcurrentQueue<object>();

async Task BanIpAsync(string ip, string? country, IMemoryCache banCache)
{
    try
    {
        await db.StringSetAsync($"shieldx:ban:{ip}", "1", banDuration);
        await subscriber.PublishAsync(RedisChannel.Literal("shieldx:bans"), ip);
    }
    catch (RedisException ex)
    {
        Logger($"[REDIS] Błąd zapisu bana IP {ip}: {ex.Message}", ConsoleColor.DarkYellow);
    }

    banCache.Set($"ban:{ip}", true, banDuration);
    Logger($"[!!!] AUTO-BAN IP: {ip} [{country ?? "??"}] → {banDuration.TotalMinutes:0} min",
           ConsoleColor.Red);

    eventBuffer.Enqueue(new
    {
        type     = "ban",
        ip,
        country  = country ?? "??",
        expiry   = DateTimeOffset.UtcNow.Add(banDuration).ToString("HH:mm:ss"),
        duration = (int)banDuration.TotalMinutes
    });
}

async Task BanFingerprintAsync(string fp, string ip, string? country,
                               int score, IMemoryCache banCache)
{
    try
    {
        await db.StringSetAsync($"shieldx:ban:fp:{fp}", ip, banDuration);
        await subscriber.PublishAsync(RedisChannel.Literal("shieldx:bans:fp"), fp);
    }
    catch (RedisException ex)
    {
        Logger($"[REDIS] Błąd zapisu bana FP {fp}: {ex.Message}", ConsoleColor.DarkYellow);
    }

    banCache.Set($"ban:fp:{fp}", true, banDuration);
    Logger($"[!!!] AUTO-BAN FP: {fp} (score={score}) IP={ip} [{country ?? "??"}] → {banDuration.TotalMinutes:0} min",
           ConsoleColor.Magenta);

    eventBuffer.Enqueue(new
    {
        type        = "bot",
        ip,
        fingerprint = fp,
        score,
        country     = country ?? "??",
        expiry      = DateTimeOffset.UtcNow.Add(banDuration).ToString("HH:mm:ss"),
        duration    = (int)banDuration.TotalMinutes
    });
}

// ── Redis Pub/Sub ─────────────────────────────────────────────────────
await subscriber.SubscribeAsync(RedisChannel.Literal("shieldx:bans"), (_, ip) =>
{
    Logger($"[SYNC] Ban IP odebrany od węzła: {ip}", ConsoleColor.Magenta);
    var cache = app.Services.GetRequiredService<IMemoryCache>();
    cache.Set($"ban:{(string)ip!}", true, banDuration);
});

await subscriber.SubscribeAsync(RedisChannel.Literal("shieldx:bans:fp"), (_, fp) =>
{
    Logger($"[SYNC] Ban FP odebrany od węzła: {fp}", ConsoleColor.Magenta);
    var cache = app.Services.GetRequiredService<IMemoryCache>();
    cache.Set($"ban:fp:{(string)fp!}", true, banDuration);
});

// =====================================================================
// PIPELINE
// =====================================================================

app.UseStaticFiles();
app.MapGet("/", () => Results.Redirect("/dashboard.html"));
app.MapHub<ShieldXHub>("/shieldx-hub");

var hubCtx   = app.Services.GetRequiredService<IHubContext<ShieldXHub>>();
var banCache = app.Services.GetRequiredService<IMemoryCache>();

// Flush timer – paczki SignalR co 1 sekundę
var flushTimer = new System.Timers.Timer(1000);
flushTimer.Elapsed += async (_, _) =>
{
    if (eventBuffer.IsEmpty) return;
    var batch = new List<object>();
    while (eventBuffer.TryDequeue(out var ev)) batch.Add(ev);
    try
    {
        foreach (var ev in batch)
        {
            dynamic d    = ev;
            string  type = (string)d.type;
            switch (type)
            {
                case "ban":
                    await hubCtx.Clients.All.SendAsync("BanEvent", ev);
                    break;
                case "violation":
                    await hubCtx.Clients.All.SendAsync("ViolationEvent", ev);
                    break;
                case "geoblock":
                    await hubCtx.Clients.All.SendAsync("GeoBlock", ev);
                    break;
                case "bot":
                    await hubCtx.Clients.All.SendAsync("BotEvent", ev);
                    break;
            }
        }
    }
    catch { }
};
flushTimer.Start();

// ── Middleware antyfrodowy ─────────────────────────────────────────────
app.Use(async (context, next) =>
{
    string clientIp = ResolveClientIp(context, trustedProxies);

    if (IPAddress.TryParse(clientIp, out var addr) && IPAddress.IsLoopback(addr))
    {
        await next();
        return;
    }

    if (whitelistedIps.Contains(clientIp))
    {
        await next();
        return;
    }

    string? country     = ResolveCountry(clientIp);
    string  fingerprint = ComputeFingerprint(context.Request);
    int     botScore    = ComputeBotScore(context.Request);

    // ── 1. Sprawdź ban IP ──────────────────────────────────────────────
    if (!banCache.TryGetValue($"ban:{clientIp}", out _))
    {
        if (await IsBannedInRedisAsync($"shieldx:ban:{clientIp}"))
            banCache.Set($"ban:{clientIp}", true, banCacheTtl);
    }

    if (banCache.TryGetValue($"ban:{clientIp}", out _))
    {
        var ttl  = await db.KeyTimeToLiveAsync($"shieldx:ban:{clientIp}");
        double m = ttl?.TotalMinutes ?? 0;
        context.Response.StatusCode = 403;
        await context.Response.WriteAsync($"IP ZABLOKOWANE. Ban wygasa za {m:0.0} minut.");
        return;
    }

    // ── 2. Sprawdź ban fingerprint ────────────────────────────────────
    if (!banCache.TryGetValue($"ban:fp:{fingerprint}", out _))
    {
        if (await IsBannedInRedisAsync($"shieldx:ban:fp:{fingerprint}"))
            banCache.Set($"ban:fp:{fingerprint}", true, banCacheTtl);
    }

    if (banCache.TryGetValue($"ban:fp:{fingerprint}", out _))
    {
        Logger($"[BOT-BAN] FP={fingerprint} IP={clientIp} [{country ?? "??"}] zablokowany",
               ConsoleColor.Magenta);
        context.Response.StatusCode = 403;
        await context.Response.WriteAsync("Zablokowano – wykryto automatyczny klient.");
        return;
    }

    // ── 3. Sprawdź Geo-IP ─────────────────────────────────────────────
    if (country is not null && blockedCountries.Contains(country))
    {
        context.Response.StatusCode = 403;
        Logger($"[GEO] Zablokowano {clientIp} [{country}]", ConsoleColor.DarkRed);
        await context.Response.WriteAsync($"Dostęp zablokowany dla regionu: {country}");
        eventBuffer.Enqueue(new { type = "geoblock", ip = clientIp, country });
        return;
    }

    // ── 4. Ocena Bot Score ────────────────────────────────────────────
    if (botScore >= botScoreThreshold)
    {
        int fpViolations = await IncrementAsync($"shieldx:violations:fp:{fingerprint}");

        Logger($"[BOT] Score={botScore} FP={fingerprint} IP={clientIp} [{country ?? "??"}] " +
               $"Naruszenia: {fpViolations}/{fpViolationLimit}",
               ConsoleColor.DarkMagenta);

        eventBuffer.Enqueue(new
        {
            type        = "bot",
            ip          = clientIp,
            fingerprint,
            score       = botScore,
            country     = country ?? "??",
            violations  = fpViolations,
            threshold   = fpViolationLimit,
            expiry      = "",
            duration    = 0
        });

        if (fpViolations >= fpViolationLimit)
        {
            await BanFingerprintAsync(fingerprint, clientIp, country, botScore, banCache);
            if (botScore >= 80)
                await BanIpAsync(clientIp, country, banCache);
        }

        context.Response.StatusCode = 403;
        await context.Response.WriteAsync("Zablokowano – wykryto automatyczny klient.");
        return;
    }

    await next();

    // ── 5. Obsługa 429 (rate limit) ───────────────────────────────────
    if (context.Response.StatusCode == 429)
    {
        int violations = await IncrementAsync($"shieldx:violations:{clientIp}");
        Logger($"[!] OSTRZEZENIE: {clientIp} [{country ?? "??"}] (Przewinienie: {violations}/3)",
               ConsoleColor.Yellow);

        eventBuffer.Enqueue(new
        {
            type      = "violation",
            ip        = clientIp,
            country   = country ?? "??",
            count     = violations,
            threshold = 3
        });

        if (violations == 3)
            await BanIpAsync(clientIp, country, banCache);
    }
});

app.UseRateLimiter();

app.MapReverseProxy(proxy =>
{
    proxy.Use(async (context, next) =>
    {
        var ip = ResolveClientIp(context, trustedProxies);
        Logger(
            $"[OK] {context.Request.Method} {context.Request.Path} " +
            $"od {ip} [{ResolveCountry(ip) ?? "??"}]",
            ConsoleColor.Green);
        await next();
    });
}).RequireRateLimiting("fixed-policy");

// ── Graceful shutdown ─────────────────────────────────────────────────
var lifetime = app.Services.GetRequiredService<IHostApplicationLifetime>();
lifetime.ApplicationStopping.Register(() =>
{
    flushTimer.Stop();
    flushTimer.Dispose();
    logChannel.Writer.Complete();
    logWriterTask.Wait(TimeSpan.FromSeconds(5));
    geoReader?.Dispose();
    redis.Dispose();
});

Logger("=== SHIELD-X V7 [GLOBAL SCALE + FINGERPRINTING] URUCHOMIONY ===", ConsoleColor.Cyan);
Logger($"    Redis              : {redisConn}",                                                                    ConsoleColor.Cyan);
Logger($"    Ban TTL            : {banDuration.TotalMinutes:0} min",                                              ConsoleColor.Cyan);
Logger($"    Ban cache TTL      : {banCacheTtl.TotalSeconds:0} s",                                                ConsoleColor.Cyan);
Logger($"    Violation TTL      : {violationDecayTtl.TotalMinutes:0} min",                                        ConsoleColor.Cyan);
Logger($"    Bot score threshold: {botScoreThreshold}/100",                                                        ConsoleColor.Cyan);
Logger($"    FP violation limit : {fpViolationLimit}",                                                            ConsoleColor.Cyan);
Logger($"    Trusted proxies    : {(trustedProxies.Count > 0 ? string.Join(", ", trustedProxies) : "brak")}",    ConsoleColor.Cyan);
Logger($"    Whitelisted IPs    : {(whitelistedIps.Count > 0 ? string.Join(", ", whitelistedIps) : "brak")}",    ConsoleColor.Cyan);
Logger($"    Geo-IP             : {(geoReader is not null ? $"aktywny ({blockedCountries.Count} krajów)" : "wyłączony")}", ConsoleColor.Cyan);
Logger($"    Proxy cel          : httpbin.org (zmień w kodzie na własny backend)",                                ConsoleColor.Cyan);
Logger($"    Dashboard          : http://localhost:5000/dashboard.html",                                           ConsoleColor.Cyan);
app.Run();

// ── SignalR Hub ───────────────────────────────────────────────────────
public class ShieldXHub : Hub
{
    public async Task RequestStats()
    {
        await Clients.Caller.SendAsync("StatsResponse", new
        {
            timestamp = DateTime.UtcNow.ToString("o"),
            message   = "Połączono z Shield-X V7 [FINGERPRINTING]"
        });
    }
}
// =====================================================================
// SHIELD-X V7 – "Global Scale" Edition + Browser Fingerprinting
// =====================================================================
// Zmiany względem poprzedniej wersji:
//   + ComputeFingerprint()  – hash SHA-256 z nagłówków HTTP
//   + BotScore()            – punktacja podejrzanych sygnałów (0-100)
//   + Bany per fingerprint  – Redis: shieldx:ban:fp:{hash}
//   + Violations per fp     – Redis: shieldx:violations:fp:{hash}
//   + Dashboard events      – BotEvent wysyłany do SignalR
//   + Whitelist IP          – zaufane IP nigdy nie dostają bana
//   + YARP path transform   – /proxy/get → /get na backendzie
// =====================================================================

using System.Threading.RateLimiting;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.SignalR;
using Microsoft.Extensions.Caching.Memory;
using Yarp.ReverseProxy.Configuration;
using System.Net;
using System.Collections.Concurrent;
using System.Threading.Channels;
using System.Security.Cryptography;
using System.Text;
using StackExchange.Redis;
using MaxMind.GeoIP2;

var builder = WebApplication.CreateBuilder(args);
var cfg     = builder.Configuration;

TimeSpan banDuration       = cfg.GetValue<TimeSpan?>("BanDuration")        ?? TimeSpan.FromHours(1);
TimeSpan violationDecayTtl = cfg.GetValue<TimeSpan?>("ViolationDecayTtl")  ?? TimeSpan.FromHours(1);
TimeSpan banCacheTtl       = cfg.GetValue<TimeSpan?>("BanCacheTtl")        ?? TimeSpan.FromSeconds(10);
string   redisConn         = cfg.GetValue<string>("Redis:ConnectionString") ?? "localhost:6379";
string   geoDbPath         = cfg.GetValue<string>("GeoIp:DbPath")           ?? "GeoLite2-Country.mmdb";
int      botScoreThreshold = cfg.GetValue<int?>("BotScoreThreshold")        ?? 60;
int      fpViolationLimit  = cfg.GetValue<int?>("FingerprintViolationLimit") ?? 5;

var blockedCountries = cfg.GetSection("GeoIp:BlockedCountries")
                          .Get<HashSet<string>>() ?? new HashSet<string>();

var trustedProxies   = cfg.GetSection("TrustedProxies")
                          .Get<HashSet<string>>() ?? new HashSet<string>();

var whitelistedIps   = cfg.GetSection("WhitelistedIps")
                          .Get<HashSet<string>>() ?? new HashSet<string>();

// ── Redis ─────────────────────────────────────────────────────────────
var redisOpts = ConfigurationOptions.Parse(redisConn);
redisOpts.AbortOnConnectFail = false;
var redis      = await ConnectionMultiplexer.ConnectAsync(redisOpts);
var db         = redis.GetDatabase();
var subscriber = redis.GetSubscriber();

// ── Geo-IP ────────────────────────────────────────────────────────────
DatabaseReader? geoReader = null;
if (File.Exists(geoDbPath))
{
    geoReader = new DatabaseReader(geoDbPath);
    Console.WriteLine($"[GEO-IP] Baza załadowana: {geoDbPath} | Blokowane: {string.Join(", ", blockedCountries)}");
}
else
{
    Console.ForegroundColor = ConsoleColor.Yellow;
    Console.WriteLine($"[GEO-IP] UWAGA: Brak pliku {geoDbPath} – blokowanie krajów wyłączone.");
    Console.ResetColor();
}

// ── Log channel ───────────────────────────────────────────────────────
var logChannel = Channel.CreateBounded<string>(new BoundedChannelOptions(4096)
{
    FullMode = BoundedChannelFullMode.DropOldest
});

var logWriterTask = Task.Run(async () =>
{
    await foreach (var entry in logChannel.Reader.ReadAllAsync())
    {
        try   { await File.AppendAllTextAsync("logs.txt", entry + Environment.NewLine); }
        catch { }
    }
});

// ── Services ──────────────────────────────────────────────────────────
builder.Services.AddSignalR();
builder.Services.AddDirectoryBrowser();
builder.Services.AddMemoryCache();

// POPRAWKA: Transformacja ścieżki – usuwa prefiks /proxy/ przed wysłaniem do backendu
// Przykład: /proxy/get → /get na docelowym serwerze
var routes = new[]
{
    new RouteConfig
    {
        RouteId    = "route1",
        ClusterId  = "cluster1",
        Match      = new RouteMatch { Path = "/proxy/{**catch-all}" },
        Transforms = new List<Dictionary<string, string>>
        {
            new Dictionary<string, string> { { "PathPattern", "/{**catch-all}" } }
        }
    }
};

var clusters = new[]
{
    new ClusterConfig
    {
        ClusterId    = "cluster1",
        Destinations = new Dictionary<string, DestinationConfig>
        {
            // httpbin.org – idealne do testów, zwraca JSON z nagłówkami i IP
            // Zmień na własny backend w produkcji
            { "dest1", new DestinationConfig { Address = "https://httpbin.org" } }
        },
        HttpRequest = new Yarp.ReverseProxy.Forwarder.ForwarderRequestConfig
        {
            ActivityTimeout = TimeSpan.FromSeconds(30)
        }
    }
};

builder.Services.AddReverseProxy().LoadFromMemory(routes, clusters);

builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.AddPolicy("fixed-policy", httpContext =>
    {
        string clientIp = ResolveClientIp(httpContext, trustedProxies);
        if (IPAddress.TryParse(clientIp, out var a) && IPAddress.IsLoopback(a))
            return RateLimitPartition.GetNoLimiter("localhost");

        return RateLimitPartition.GetFixedWindowLimiter(clientIp,
            _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 30,
                Window      = TimeSpan.FromSeconds(10)
            });
    });
});

var app = builder.Build();

// ── Helpers ───────────────────────────────────────────────────────────

static string ResolveClientIp(HttpContext ctx, HashSet<string> trustedProxies)
{
    var remoteIp = ctx.Connection.RemoteIpAddress?.ToString();
    if (remoteIp != null && trustedProxies.Contains(remoteIp))
    {
        var forwarded = ctx.Request.Headers["X-Forwarded-For"].FirstOrDefault();
        if (!string.IsNullOrWhiteSpace(forwarded))
        {
            var first = forwarded.Split(',')[0].Trim();
            if (IPAddress.TryParse(first, out _)) return first;
        }
    }
    return remoteIp ?? "::1";
}

string? ResolveCountry(string ip)
{
    if (geoReader is null) return null;
    if (!IPAddress.TryParse(ip, out var addr) || IPAddress.IsLoopback(addr)) return null;
    try   { return geoReader.Country(ip).Country.IsoCode; }
    catch { return null; }
}

void Logger(string message, ConsoleColor color = ConsoleColor.Gray)
{
    string logEntry = $"[{DateTime.Now:HH:mm:ss}] {message}";
    Console.ForegroundColor = color;
    Console.WriteLine(logEntry);
    Console.ResetColor();
    logChannel.Writer.TryWrite(logEntry);
}

// ── Fingerprinting ────────────────────────────────────────────────────

static string ComputeFingerprint(HttpRequest req)
{
    var ua      = req.Headers["User-Agent"].ToString();
    var al      = req.Headers["Accept-Language"].ToString();
    var ae      = req.Headers["Accept-Encoding"].ToString();
    var acc     = req.Headers["Accept"].ToString();
    var sec     = req.Headers["Sec-Ch-Ua"].ToString();
    var secMob  = req.Headers["Sec-Ch-Ua-Mobile"].ToString();
    var secPlat = req.Headers["Sec-Ch-Ua-Platform"].ToString();
    var order   = string.Join(",", req.Headers.Keys.Take(8));

    var raw  = $"{ua}|{al}|{ae}|{acc}|{sec}|{secMob}|{secPlat}|{order}";
    var hash = SHA256.HashData(Encoding.UTF8.GetBytes(raw));
    return Convert.ToHexString(hash)[..16];
}

static int ComputeBotScore(HttpRequest req)
{
    int score = 0;
    var ua = req.Headers["User-Agent"].ToString();

    if (string.IsNullOrWhiteSpace(ua))
    {
        score += 40;
    }
    else
    {
        string[] botSignatures =
        [
            "curl", "wget", "python-requests", "python-urllib",
            "go-http-client", "java/", "okhttp", "axios",
            "libwww-perl", "scrapy", "bot", "crawler", "spider",
            "headless", "phantomjs", "selenium", "playwright"
        ];
        if (botSignatures.Any(sig => ua.Contains(sig, StringComparison.OrdinalIgnoreCase)))
            score += 35;
    }

    if (string.IsNullOrWhiteSpace(req.Headers["Accept-Language"]))  score += 20;
    if (string.IsNullOrWhiteSpace(req.Headers["Accept-Encoding"]))  score += 15;
    if (string.IsNullOrWhiteSpace(req.Headers["Accept"]))           score += 10;
    if (!string.IsNullOrWhiteSpace(req.Headers["Postman-Token"]))   score += 10;
    if (string.IsNullOrWhiteSpace(req.Headers["Cookie"]))           score += 5;

    return Math.Min(score, 100);
}

// ── Circuit Breaker ───────────────────────────────────────────────────

async Task<bool> IsBannedInRedisAsync(string key)
{
    try   { return (await db.StringGetAsync(key)).HasValue; }
    catch (RedisException ex)
    {
        Logger($"[REDIS] Błąd ban-check {key}: {ex.Message}", ConsoleColor.DarkYellow);
        return false;
    }
}

async Task<int> IncrementAsync(string key)
{
    try
    {
        long count = await db.StringIncrementAsync(key);
        if (count == 1) await db.KeyExpireAsync(key, violationDecayTtl);
        return (int)count;
    }
    catch (RedisException ex)
    {
        Logger($"[REDIS] Błąd increment {key}: {ex.Message}", ConsoleColor.DarkYellow);
        return 0;
    }
}

// ── Event buffer ──────────────────────────────────────────────────────
var eventBuffer = new ConcurrentQueue<object>();

async Task BanIpAsync(string ip, string? country, IMemoryCache banCache)
{
    try
    {
        await db.StringSetAsync($"shieldx:ban:{ip}", "1", banDuration);
        await subscriber.PublishAsync(RedisChannel.Literal("shieldx:bans"), ip);
    }
    catch (RedisException ex)
    {
        Logger($"[REDIS] Błąd zapisu bana IP {ip}: {ex.Message}", ConsoleColor.DarkYellow);
    }

    banCache.Set($"ban:{ip}", true, banDuration);
    Logger($"[!!!] AUTO-BAN IP: {ip} [{country ?? "??"}] → {banDuration.TotalMinutes:0} min",
           ConsoleColor.Red);

    eventBuffer.Enqueue(new
    {
        type     = "ban",
        ip,
        country  = country ?? "??",
        expiry   = DateTimeOffset.UtcNow.Add(banDuration).ToString("HH:mm:ss"),
        duration = (int)banDuration.TotalMinutes
    });
}

async Task BanFingerprintAsync(string fp, string ip, string? country,
                               int score, IMemoryCache banCache)
{
    try
    {
        await db.StringSetAsync($"shieldx:ban:fp:{fp}", ip, banDuration);
        await subscriber.PublishAsync(RedisChannel.Literal("shieldx:bans:fp"), fp);
    }
    catch (RedisException ex)
    {
        Logger($"[REDIS] Błąd zapisu bana FP {fp}: {ex.Message}", ConsoleColor.DarkYellow);
    }

    banCache.Set($"ban:fp:{fp}", true, banDuration);
    Logger($"[!!!] AUTO-BAN FP: {fp} (score={score}) IP={ip} [{country ?? "??"}] → {banDuration.TotalMinutes:0} min",
           ConsoleColor.Magenta);

    eventBuffer.Enqueue(new
    {
        type        = "bot",
        ip,
        fingerprint = fp,
        score,
        country     = country ?? "??",
        expiry      = DateTimeOffset.UtcNow.Add(banDuration).ToString("HH:mm:ss"),
        duration    = (int)banDuration.TotalMinutes
    });
}

// ── Redis Pub/Sub ─────────────────────────────────────────────────────
await subscriber.SubscribeAsync(RedisChannel.Literal("shieldx:bans"), (_, ip) =>
{
    Logger($"[SYNC] Ban IP odebrany od węzła: {ip}", ConsoleColor.Magenta);
    var cache = app.Services.GetRequiredService<IMemoryCache>();
    cache.Set($"ban:{(string)ip!}", true, banDuration);
});

await subscriber.SubscribeAsync(RedisChannel.Literal("shieldx:bans:fp"), (_, fp) =>
{
    Logger($"[SYNC] Ban FP odebrany od węzła: {fp}", ConsoleColor.Magenta);
    var cache = app.Services.GetRequiredService<IMemoryCache>();
    cache.Set($"ban:fp:{(string)fp!}", true, banDuration);
});

// =====================================================================
// PIPELINE
// =====================================================================

app.UseStaticFiles();
app.MapGet("/", () => Results.Redirect("/dashboard.html"));
app.MapHub<ShieldXHub>("/shieldx-hub");

var hubCtx   = app.Services.GetRequiredService<IHubContext<ShieldXHub>>();
var banCache = app.Services.GetRequiredService<IMemoryCache>();

// Flush timer – paczki SignalR co 1 sekundę
var flushTimer = new System.Timers.Timer(1000);
flushTimer.Elapsed += async (_, _) =>
{
    if (eventBuffer.IsEmpty) return;
    var batch = new List<object>();
    while (eventBuffer.TryDequeue(out var ev)) batch.Add(ev);
    try
    {
        foreach (var ev in batch)
        {
            dynamic d    = ev;
            string  type = (string)d.type;
            switch (type)
            {
                case "ban":
                    await hubCtx.Clients.All.SendAsync("BanEvent", ev);
                    break;
                case "violation":
                    await hubCtx.Clients.All.SendAsync("ViolationEvent", ev);
                    break;
                case "geoblock":
                    await hubCtx.Clients.All.SendAsync("GeoBlock", ev);
                    break;
                case "bot":
                    await hubCtx.Clients.All.SendAsync("BotEvent", ev);
                    break;
            }
        }
    }
    catch { }
};
flushTimer.Start();

// ── Middleware antyfrodowy ─────────────────────────────────────────────
app.Use(async (context, next) =>
{
    string clientIp = ResolveClientIp(context, trustedProxies);

    if (IPAddress.TryParse(clientIp, out var addr) && IPAddress.IsLoopback(addr))
    {
        await next();
        return;
    }

    if (whitelistedIps.Contains(clientIp))
    {
        await next();
        return;
    }

    string? country     = ResolveCountry(clientIp);
    string  fingerprint = ComputeFingerprint(context.Request);
    int     botScore    = ComputeBotScore(context.Request);

    // ── 1. Sprawdź ban IP ──────────────────────────────────────────────
    if (!banCache.TryGetValue($"ban:{clientIp}", out _))
    {
        if (await IsBannedInRedisAsync($"shieldx:ban:{clientIp}"))
            banCache.Set($"ban:{clientIp}", true, banCacheTtl);
    }

    if (banCache.TryGetValue($"ban:{clientIp}", out _))
    {
        var ttl  = await db.KeyTimeToLiveAsync($"shieldx:ban:{clientIp}");
        double m = ttl?.TotalMinutes ?? 0;
        context.Response.StatusCode = 403;
        await context.Response.WriteAsync($"IP ZABLOKOWANE. Ban wygasa za {m:0.0} minut.");
        return;
    }

    // ── 2. Sprawdź ban fingerprint ────────────────────────────────────
    if (!banCache.TryGetValue($"ban:fp:{fingerprint}", out _))
    {
        if (await IsBannedInRedisAsync($"shieldx:ban:fp:{fingerprint}"))
            banCache.Set($"ban:fp:{fingerprint}", true, banCacheTtl);
    }

    if (banCache.TryGetValue($"ban:fp:{fingerprint}", out _))
    {
        Logger($"[BOT-BAN] FP={fingerprint} IP={clientIp} [{country ?? "??"}] zablokowany",
               ConsoleColor.Magenta);
        context.Response.StatusCode = 403;
        await context.Response.WriteAsync("Zablokowano – wykryto automatyczny klient.");
        return;
    }

    // ── 3. Sprawdź Geo-IP ─────────────────────────────────────────────
    if (country is not null && blockedCountries.Contains(country))
    {
        context.Response.StatusCode = 403;
        Logger($"[GEO] Zablokowano {clientIp} [{country}]", ConsoleColor.DarkRed);
        await context.Response.WriteAsync($"Dostęp zablokowany dla regionu: {country}");
        eventBuffer.Enqueue(new { type = "geoblock", ip = clientIp, country });
        return;
    }

    // ── 4. Ocena Bot Score ────────────────────────────────────────────
    if (botScore >= botScoreThreshold)
    {
        int fpViolations = await IncrementAsync($"shieldx:violations:fp:{fingerprint}");

        Logger($"[BOT] Score={botScore} FP={fingerprint} IP={clientIp} [{country ?? "??"}] " +
               $"Naruszenia: {fpViolations}/{fpViolationLimit}",
               ConsoleColor.DarkMagenta);

        eventBuffer.Enqueue(new
        {
            type        = "bot",
            ip          = clientIp,
            fingerprint,
            score       = botScore,
            country     = country ?? "??",
            violations  = fpViolations,
            threshold   = fpViolationLimit,
            expiry      = "",
            duration    = 0
        });

        if (fpViolations >= fpViolationLimit)
        {
            await BanFingerprintAsync(fingerprint, clientIp, country, botScore, banCache);
            if (botScore >= 80)
                await BanIpAsync(clientIp, country, banCache);
        }

        context.Response.StatusCode = 403;
        await context.Response.WriteAsync("Zablokowano – wykryto automatyczny klient.");
        return;
    }

    await next();

    // ── 5. Obsługa 429 (rate limit) ───────────────────────────────────
    if (context.Response.StatusCode == 429)
    {
        int violations = await IncrementAsync($"shieldx:violations:{clientIp}");
        Logger($"[!] OSTRZEZENIE: {clientIp} [{country ?? "??"}] (Przewinienie: {violations}/3)",
               ConsoleColor.Yellow);

        eventBuffer.Enqueue(new
        {
            type      = "violation",
            ip        = clientIp,
            country   = country ?? "??",
            count     = violations,
            threshold = 3
        });

        if (violations == 3)
            await BanIpAsync(clientIp, country, banCache);
    }
});

app.UseRateLimiter();

app.MapReverseProxy(proxy =>
{
    proxy.Use(async (context, next) =>
    {
        var ip = ResolveClientIp(context, trustedProxies);
        Logger(
            $"[OK] {context.Request.Method} {context.Request.Path} " +
            $"od {ip} [{ResolveCountry(ip) ?? "??"}]",
            ConsoleColor.Green);
        await next();
    });
}).RequireRateLimiting("fixed-policy");

// ── Graceful shutdown ─────────────────────────────────────────────────
var lifetime = app.Services.GetRequiredService<IHostApplicationLifetime>();
lifetime.ApplicationStopping.Register(() =>
{
    flushTimer.Stop();
    flushTimer.Dispose();
    logChannel.Writer.Complete();
    logWriterTask.Wait(TimeSpan.FromSeconds(5));
    geoReader?.Dispose();
    redis.Dispose();
});

Logger("=== SHIELD-X V7 [GLOBAL SCALE + FINGERPRINTING] URUCHOMIONY ===", ConsoleColor.Cyan);
Logger($"    Redis              : {redisConn}",                                                                    ConsoleColor.Cyan);
Logger($"    Ban TTL            : {banDuration.TotalMinutes:0} min",                                              ConsoleColor.Cyan);
Logger($"    Ban cache TTL      : {banCacheTtl.TotalSeconds:0} s",                                                ConsoleColor.Cyan);
Logger($"    Violation TTL      : {violationDecayTtl.TotalMinutes:0} min",                                        ConsoleColor.Cyan);
Logger($"    Bot score threshold: {botScoreThreshold}/100",                                                        ConsoleColor.Cyan);
Logger($"    FP violation limit : {fpViolationLimit}",                                                            ConsoleColor.Cyan);
Logger($"    Trusted proxies    : {(trustedProxies.Count > 0 ? string.Join(", ", trustedProxies) : "brak")}",    ConsoleColor.Cyan);
Logger($"    Whitelisted IPs    : {(whitelistedIps.Count > 0 ? string.Join(", ", whitelistedIps) : "brak")}",    ConsoleColor.Cyan);
Logger($"    Geo-IP             : {(geoReader is not null ? $"aktywny ({blockedCountries.Count} krajów)" : "wyłączony")}", ConsoleColor.Cyan);
Logger($"    Proxy cel          : httpbin.org (zmień w kodzie na własny backend)",                                ConsoleColor.Cyan);
Logger($"    Dashboard          : http://localhost:5000/dashboard.html",                                           ConsoleColor.Cyan);
app.Run();

// ── SignalR Hub ───────────────────────────────────────────────────────
public class ShieldXHub : Hub
{
    public async Task RequestStats()
    {
        await Clients.Caller.SendAsync("StatsResponse", new
        {
            timestamp = DateTime.UtcNow.ToString("o"),
            message   = "Połączono z Shield-X V7 [FINGERPRINTING]"
        });
    }
}
