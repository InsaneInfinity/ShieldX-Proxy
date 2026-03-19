# 🚀 WebStressTester v2.0

[🇵🇱 Polski](#-polski) | [🇬🇧 English](#-english)

---

## 🇵🇱 Polski

**WebStressTester** to profesjonalne i ultra-lekkie narzędzie napisane w **C# (.NET 10)**, przeznaczone do przeprowadzania testów obciążeniowych (stress testing) stron i aplikacji internetowych. Program wykorzystuje najnowocześniejszy silnik asynchroniczny `Parallel.ForEachAsync`, zapewniając maksymalną wydajność przy minimalnym zużyciu zasobów systemowych.

### ✨ Funkcje
* **🏎️ Silnik Parallel:** Wykorzystuje pełną moc procesora dzięki `Parallel.ForEachAsync`.
* **🕵️ Tryb Stealth:** Symuluje nagłówki przeglądarki Google Chrome (User-Agent, Accept-Language).
* **📊 Monitorowanie na żywo:** Interaktywny pasek postępu i statystyki w czasie rzeczywistym.
* **🛡️ Wykrywanie banów:** Automatycznie wychwytuje błędy HTTP 429 (Rate Limit) i inne kody błędów.
* **📑 Raporty CSV:** Każdy test jest automatycznie zapisywany do pliku `results.csv`.
* **⏱️ Inteligentny Timeout:** Automatyczne zamykanie wiszących połączeń po 10 sekundach.

### ⚠️ Oświadczenie / Disclaimer
Ten program został stworzony **wyłącznie w celach edukacyjnych** oraz do testowania infrastruktury, do której użytkownik posiada pełne prawa. Autor nie ponosi odpowiedzialności za niewłaściwe użycie tego kodu.

---

## 🇬🇧 English

**WebStressTester** is a professional, ultra-lightweight tool written in **C# (.NET 10)** for stress testing websites and web applications. It uses the modern `Parallel.ForEachAsync` engine to ensure maximum performance with minimal system overhead.

### ✨ Features
* **🏎️ Parallel Engine:** Leverages full CPU power using asynchronous parallelism.
* **🕵️ Stealth Mode:** Simulates real Google Chrome browser headers.
* **📊 Live Monitoring:** Interactive progress bar and real-time statistics.
* **🛡️ Ban Detection:** Automatically catches HTTP 429 (Rate Limit) and other error codes.
* **📑 CSV Reports:** Every test session is automatically saved to `results.csv`.
* **⏱️ Smart Timeout:** Auto-closes hanging connections after 10 seconds.

### ⚠️ Disclaimer
This tool is for **educational purposes only** and for testing infrastructure you own or have permission to test. The author is not responsible for any misuse or damage caused by this code.