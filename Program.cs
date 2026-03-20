// =====================================================================
// SHIELD-X V7 – "Global Scale" Edition
// =====================================================================
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.SignalR;
using Yarp.ReverseProxy.Configuration;
using System.Net;
using System.Collections.Concurrent;
using System.Threading.Channels;
using StackExchange.Redis;
using MaxMind.GeoIP2;

var builder = WebApplication.CreateBuilder(args);
var cfg     = builder.Configuration;

TimeSpan banDuration       = cfg.GetValue<TimeSpan?>("BanDuration")        ?? TimeSpan.FromHours(1);
TimeSpan violationDecayTtl = cfg.GetValue<TimeSpan?>("ViolationDecayTtl")  ?? TimeSpan.FromHours(1);
string   redisConn         = cfg.GetValue<string>("Redis:ConnectionString") ?? "localhost:6379";
string   geoDbPath         = cfg.GetValue<string>("GeoIp:DbPath")           ?? "GeoLite2-Country.mmdb";

var blockedCountries = cfg.GetSection("GeoIp:BlockedCountries")
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

// ── Violation counter ─────────────────────────────────────────────────
var violationCounter = new ConcurrentDictionary<string, (int Count, DateTimeOffset LastSeen)>();

async Task<int> IncrementViolationsAsync(string ip)
{
    var now         = DateTimeOffset.UtcNow;
    long redisCount = await db.StringIncrementAsync($"shieldx:violations:{ip}");
    await db.KeyExpireAsync($"shieldx:violations:{ip}", violationDecayTtl);
    violationCounter.AddOrUpdate(ip,
        addValue: ((int)redisCount, now),
        updateValueFactory: (_, old) => ((int)redisCount, now));
    return (int)redisCount;
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

// YARP – teraz przechwytuje tylko /proxy/... a nie wszystko
// dzięki temu dashboard.html i SignalR działają bez przeszkód
var routes = new[]
{
    new RouteConfig
    {
        RouteId   = "route1",
        ClusterId = "cluster1",
        Match     = new RouteMatch { Path = "/proxy/{**catch-all}" }
    }
};

var clusters = new[]
{
    new ClusterConfig
    {
        ClusterId    = "cluster1",
        Destinations = new Dictionary<string, DestinationConfig>
        {
            { "dest1", new DestinationConfig { Address = "https://www.google.com" } }
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
        string clientIp = ResolveClientIp(httpContext);
        if (IPAddress.TryParse(clientIp, out var a) && IPAddress.IsLoopback(a))
            return RateLimitPartition.GetNoLimiter("localhost");

        return RateLimitPartition.GetFixedWindowLimiter(clientIp,
            _ => new FixedWindowRateLimiterOptions { PermitLimit = 5, Window = TimeSpan.FromSeconds(10) });
    });
});

var app = builder.Build();

// ── Helpers ───────────────────────────────────────────────────────────

static string ResolveClientIp(HttpContext ctx)
{
    var forwarded = ctx.Request.Headers["X-Forwarded-For"].FirstOrDefault();
    if (!string.IsNullOrWhiteSpace(forwarded))
    {
        var first = forwarded.Split(',')[0].Trim();
        if (IPAddress.TryParse(first, out _)) return first;
    }
    return ctx.Connection.RemoteIpAddress?.ToString() ?? "::1";
}

string? ResolveCountry(string ip)
{
    if (geoReader is null) return null;
    if (!IPAddress.TryParse(ip, out var addr) || IPAddress.IsLoopback(addr)) return null;
    try   { return geoReader.Country(ip).Country.IsoCode; }
    catch { return null; }
}

IHubContext<ShieldXHub>? hubCtx = null;

void Logger(string message, ConsoleColor color = ConsoleColor.Gray)
{
    string logEntry = $"[{DateTime.Now:HH:mm:ss}] {message}";
    Console.ForegroundColor = color;
    Console.WriteLine(logEntry);
    Console.ResetColor();
    logChannel.Writer.TryWrite(logEntry);
}

async Task BanIpAsync(string ip, string? country, IHubContext<ShieldXHub> hub)
{
    await db.StringSetAsync($"shieldx:ban:{ip}", "1", banDuration);
    await subscriber.PublishAsync(RedisChannel.Literal("shieldx:bans"), ip);

    Logger($"[!!!] AUTO-BAN: {ip} [{country ?? "??"}] → wygasa za {banDuration.TotalMinutes:0} min",
           ConsoleColor.Red);

    await hub.Clients.All.SendAsync("BanEvent", new
    {
        ip,
        country  = country ?? "??",
        expiry   = DateTimeOffset.UtcNow.Add(banDuration).ToString("HH:mm:ss"),
        duration = (int)banDuration.TotalMinutes
    });
}

// ── Redis Pub/Sub ─────────────────────────────────────────────────────
await subscriber.SubscribeAsync(RedisChannel.Literal("shieldx:bans"), (channel, ip) =>
{
    Logger($"[SYNC] Ban odebrany od innego węzła: {ip}", ConsoleColor.Magenta);
});

// =====================================================================
// PIPELINE
// =====================================================================

// KROK 1: Pliki statyczne – przed wszystkim innym
app.UseStaticFiles();
app.MapGet("/", () => Results.Redirect("/dashboard.html"));

// KROK 2: SignalR hub
app.MapHub<ShieldXHub>("/shieldx-hub");

// KROK 3: Middleware antyfrodowy
app.Use(async (context, next) =>
{
    string clientIp = ResolveClientIp(context);

    if (IPAddress.TryParse(clientIp, out var addr) && IPAddress.IsLoopback(addr))
    {
        await next();
        return;
    }

    hubCtx ??= context.RequestServices.GetRequiredService<IHubContext<ShieldXHub>>();

    // Sprawdź ban w Redisie
    bool isBanned = (await db.StringGetAsync($"shieldx:ban:{clientIp}")).HasValue;
    if (isBanned)
    {
        var ttl        = await db.KeyTimeToLiveAsync($"shieldx:ban:{clientIp}");
        double minutes = ttl?.TotalMinutes ?? 0;
        context.Response.StatusCode = 403;
        await context.Response.WriteAsync($"IP ZABLOKOWANE. Ban wygasa za {minutes:0.0} minut.");
        return;
    }

    // Sprawdź kraj
    string? country = ResolveCountry(clientIp);
    if (country is not null && blockedCountries.Contains(country))
    {
        context.Response.StatusCode = 403;
        Logger($"[GEO] Zablokowano {clientIp} [{country}]", ConsoleColor.DarkRed);
        await context.Response.WriteAsync($"Dostęp zablokowany dla regionu: {country}");
        await hubCtx.Clients.All.SendAsync("GeoBlock", new { ip = clientIp, country });
        return;
    }

    await next();

    if (context.Response.StatusCode == 429)
    {
        int violations = await IncrementViolationsAsync(clientIp);
        Logger($"[!] OSTRZEZENIE: {clientIp} [{country ?? "??"}] (Przewinienie: {violations}/3)",
               ConsoleColor.Yellow);

        await hubCtx.Clients.All.SendAsync("ViolationEvent", new
        {
            ip        = clientIp,
            country   = country ?? "??",
            count     = violations,
            threshold = 3
        });

        if (violations >= 3)
            await BanIpAsync(clientIp, country, hubCtx);
    }
});

// KROK 4: Rate limiter
app.UseRateLimiter();

// KROK 5: YARP proxy (tylko /proxy/...)
app.MapReverseProxy(proxy =>
{
    proxy.Use(async (context, next) =>
    {
        Logger(
            $"[OK] {context.Request.Method} {context.Request.Path} " +
            $"od {ResolveClientIp(context)} [{ResolveCountry(ResolveClientIp(context)) ?? "??"}]",
            ConsoleColor.Green);
        await next();
    });
}).RequireRateLimiting("fixed-policy");

// ── Graceful shutdown ─────────────────────────────────────────────────
var lifetime = app.Services.GetRequiredService<IHostApplicationLifetime>();
lifetime.ApplicationStopping.Register(() =>
{
    logChannel.Writer.Complete();
    logWriterTask.Wait(TimeSpan.FromSeconds(5));
    geoReader?.Dispose();
    redis.Dispose();
});

Logger("=== SHIELD-X V7 [GLOBAL SCALE] URUCHOMIONY ===", ConsoleColor.Cyan);
Logger($"    Redis         : {redisConn}", ConsoleColor.Cyan);
Logger($"    Ban TTL       : {banDuration.TotalMinutes:0} min", ConsoleColor.Cyan);
Logger($"    Violation TTL : {violationDecayTtl.TotalMinutes:0} min", ConsoleColor.Cyan);
Logger($"    Geo-IP        : {(geoReader is not null ? $"aktywny ({blockedCountries.Count} krajów)" : "wyłączony")}", ConsoleColor.Cyan);
Logger($"    Dashboard     : http://localhost:5000/dashboard.html", ConsoleColor.Cyan);
app.Run();

// ── SignalR Hub ───────────────────────────────────────────────────────
public class ShieldXHub : Hub
{
    public async Task RequestStats()
    {
        await Clients.Caller.SendAsync("StatsResponse", new
        {
            timestamp = DateTime.UtcNow.ToString("o"),
            message   = "Połączono z Shield-X V7"
        });
    }
}
