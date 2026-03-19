# WebStressTester 🚀

*[English version below]*

Proste i lekkie narzędzie napisane w C# (.NET) przeznaczone do przeprowadzania testów obciążeniowych (stress testing) stron i aplikacji internetowych. Program działa w konsoli, wykorzystuje asynchroniczność (`Task`, `SemaphoreSlim`) i na żywo rysuje pasek postępu oraz kategoryzuje błędy (w tym wykrywa blokady Rate Limit - błąd 429).

## Funkcje
* 🕵️ **Tryb Stealth:** Symuluje nagłówki przeglądarki Google Chrome.
* 📊 **Monitorowanie na żywo:** Pasek postępu i statystyki w czasie rzeczywistym.
* 🛡️ **Wykrywanie banów:** Automatycznie wychwytuje zabezpieczenia WAF / Rate Limit.
* ⏱️ **Inteligentny Timeout:** Urywa zawieszone połączenia po 10 sekundach.

## ⚠️ Oświadczenie / Disclaimer
Ten program został stworzony **wyłącznie w celach edukacyjnych** oraz do testowania obciążeniowego infrastruktury, do której użytkownik posiada pełne prawa lub wyraźną zgodę właściciela. Autor nie ponosi żadnej odpowiedzialności za szkody, przerwy w działaniu usług ani konsekwencje prawne wynikające z niewłaściwego lub nielegalnego użycia tego kodu.

---

# WebStressTester (English) 🚀
A simple, lightweight C# (.NET) console tool for HTTP stress testing. It uses asynchronous tasks to simulate multiple concurrent users and provides a live progress bar with detailed error categorization (including 429 Rate Limit detection).

## ⚠️ Disclaimer
This tool is for **educational purposes only** and for load testing systems where you have explicit permission from the owner. The author assumes no liability and is not responsible for any misuse, damage, or legal consequences caused by this script. Use responsibly.