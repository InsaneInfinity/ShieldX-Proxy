using System;
using System.Diagnostics;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Concurrent;
using System.Linq;

namespace WebStressTester
{
    class Program
    {
        private static readonly HttpClient client = new HttpClient();
        
        private static int completedRequests = 0;
        private static int successCount = 0;
        private static int rateLimitCount = 0;
        
        // Zamiast jednej zmiennej "errorCount", używamy inteligentnego słownika do kategoryzowania błędów
        private static ConcurrentDictionary<string, int> errorDetails = new ConcurrentDictionary<string, int>();
        
        private static readonly object consoleLock = new object();

        static async Task Main(string[] args)
        {
            // --- TRYB STEALTH: KAMUFLAŻ PRZEGLĄDARKI ---
            // Udajemy najnowszego Google Chrome na Windows 11
            client.DefaultRequestHeaders.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36");
            client.DefaultRequestHeaders.Add("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8");
            client.DefaultRequestHeaders.Add("Accept-Language", "pl-PL,pl;q=0.9,en-US;q=0.8,en;q=0.7");
            client.DefaultRequestHeaders.Add("Upgrade-Insecure-Requests", "1");
            
            // Ucinamy połączenie po 10 sekundach milczenia serwera (żeby program nie wisiał jak ostatnio)
            client.Timeout = TimeSpan.FromSeconds(10); 

            Console.Clear();
            Console.WriteLine("=== Tester Wytrzymałości (Tryb Stealth) ===\n");
            
            Console.Write("Podaj adres strony [domyślnie: https://example.com]: ");
            string targetUrl = Console.ReadLine();
            if (string.IsNullOrWhiteSpace(targetUrl)) targetUrl = "https://example.com";
            if (!targetUrl.StartsWith("http")) targetUrl = "https://" + targetUrl;

            Console.Write("Podaj całkowitą liczbę zapytań [domyślnie: 100]: ");
            if (!int.TryParse(Console.ReadLine(), out int numberOfRequests)) numberOfRequests = 100;

            Console.Write("Podaj liczbę jednoczesnych połączeń [domyślnie: 10]: ");
            if (!int.TryParse(Console.ReadLine(), out int concurrentUsers)) concurrentUsers = 10;

            Console.WriteLine($"\nCel: {targetUrl}");
            Console.WriteLine($"Liczba zapytań: {numberOfRequests}, Jednocześnie: {concurrentUsers}");
            Console.WriteLine("Rozpoczynam testowanie...\n\n");

            var stopWatch = Stopwatch.StartNew();
            var semaphore = new SemaphoreSlim(concurrentUsers);
            var tasks = new Task[numberOfRequests];
            
            int progressLine = Console.CursorTop - 1;

            for (int i = 0; i < numberOfRequests; i++)
            {
                tasks[i] = Task.Run(async () =>
                {
                    await semaphore.WaitAsync();
                    try
                    {
                        var response = await client.GetAsync(targetUrl);
                        
                        if (response.IsSuccessStatusCode)
                        {
                            Interlocked.Increment(ref successCount);
                        }
                        else if ((int)response.StatusCode == 429)
                        {
                            Interlocked.Increment(ref rateLimitCount);
                        }
                        else
                        {
                            // Serwer zwrócił inny błąd - zapisujemy dokładny kod (np. "403 Forbidden")
                            string errorName = $"{(int)response.StatusCode} {response.ReasonPhrase}";
                            errorDetails.AddOrUpdate(errorName, 1, (key, oldValue) => oldValue + 1);
                        }
                    }
                    catch (TaskCanceledException)
                    {
                        // Jeśli minie 10 sekund i serwer nie odpowie (nasz nowy Timeout)
                        errorDetails.AddOrUpdate("Timeout (Brak odpowiedzi w 10s)", 1, (key, oldValue) => oldValue + 1);
                    }
                    catch (Exception ex)
                    {
                        // Inne twarde błędy sieciowe (np. brak internetu, odrzucenie połączenia)
                        errorDetails.AddOrUpdate($"Błąd sieci: {ex.GetType().Name}", 1, (key, oldValue) => oldValue + 1);
                    }
                    finally
                    {
                        semaphore.Release();
                        int completed = Interlocked.Increment(ref completedRequests);
                        DrawProgressBar(completed, numberOfRequests, progressLine);
                    }
                });
            }

            await Task.WhenAll(tasks);
            stopWatch.Stop();

            Console.CursorVisible = true;
            Console.WriteLine("\n\n=== Podsumowanie Testu ===");
            Console.WriteLine($"Czas trwania: {stopWatch.ElapsedMilliseconds} ms");
            Console.WriteLine($"Udane zapytania (200 OK): {successCount}");
            
            if (rateLimitCount > 0)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"Zablokowane zapytania (Ban 429): {rateLimitCount}");
                Console.ResetColor();
            }

            // Wypisujemy dokładną listę innych błędów
            int totalOtherErrors = errorDetails.Values.Sum();
            Console.WriteLine($"Inne błędy łącznie: {totalOtherErrors}");
            
            if (totalOtherErrors > 0)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("Szczegóły błędów:");
                foreach (var error in errorDetails)
                {
                    Console.WriteLine($"  -> {error.Key}: {error.Value} razy");
                }
                Console.ResetColor();
            }
        }

        static void DrawProgressBar(int complete, int total, int line)
        {
            lock (consoleLock)
            {
                Console.CursorVisible = false;
                int barSize = 30;
                double percent = (double)complete / total;
                int chars = (int)(percent * barSize);
                
                string p1 = new string('█', chars);
                string p2 = new string('░', barSize - chars);

                // Liczymy łączną sumę innych błędów do paska
                int currentOtherErrors = errorDetails.Values.Sum();

                Console.SetCursorPosition(0, line);
                Console.Write($"[{p1}{p2}] {percent:P0} | OK: {successCount} | Błędy: {currentOtherErrors} | ");
                
                if (rateLimitCount > 0) Console.ForegroundColor = ConsoleColor.Red;
                Console.Write($"Bany (429): {rateLimitCount}");
                Console.ResetColor();
                Console.Write("          "); 
            }
        }
    }
}