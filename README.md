# AegisCore Endpoint Security (SuperLX 1.0 & AEGIS-VORTEX)

Windows için geliştirilmiş, sıfır harici bağımlılıklı (zero third-party dependency), çok katmanlı (polyglot) uç nokta güvenlik ve gerçek zamanlı tehdit koruma platformu.

## Hazır `.exe` İndirme (Kurulum Gerektirmez)

[GitHub Releases](https://github.com/fkalsasx/AegisCore/releases/latest) sayfasından iki farklı tam bağımsız paketten birini indirebilirsiniz (hedef Windows 10/11 64-bit bilgisayarda Node.js, Python veya .NET kurulu olması **gerekmez**):

- **`AegisCore-v6.0.0-Setup.exe`** — Türkçe/İngilizce kurulum sihirbazı (Başlat Menüsü, Masaüstü kısayolu ve isteğe bağlı başlangıçta sistem tepsisinde açılma)
- **`AegisCore-v6.0.0-win-x64-portable.zip`** — Kurulumsuz taşınabilir paket (klasöre çıkarıp `AegisCore.exe` dosyasına çift tıklamanız yeterli)

## Mimari Katmanlar

| Katman | Teknoloji | Görev |
| :--- | :--- | :--- |
| **Masaüstü Başlatıcı (`AegisCore.exe`)** | C# (.NET 8 Win32) | Konsolsuz tek-örnek (single-instance) başlatıcı, sistem tepsisi menüsü ve Job Object temiz kapanış garantisi (`launcher/`) |
| **Native Tarama & Ağ Çekirdeği** | C# (.NET 8) | Çok çekirdekli dosya/disk tarama, PE yapısal analiz, Authenticode & Windows Security Catalog doğrulaması, çekirdek TCP/UDP-PID ağ izleme (`engines/csharp-scanner/`) |
| **Sezgisel & Anti-RAT Motoru** | Python 3.10+ (`SuperLX 1.0`) | Gelişmiş betik/PE/entropi analizi, obfuscation & Base64/GZip çözümleme, LOLBin / RAT / Defender bypass tespiti (`engines/superlx/`, `engines/python-heuristics/`) |
| **AEGIS-VORTEX Davranış Daemon'ı** | Python 3.10+ + Win32 API | 6+1 modüllü canlı süreç soy ağacı, Canary fidye tuzağı, Gölge Kafes mikro-sandbox, Risk Barometresi, Atomik Zaman Makinesi (LIFO rollback) ve AES-256-GCM kasa (`vortex/`) |
| **Orkestratör & Web Paneli** | Node.js + Vanilla HTML/CSS/JS | Gerçek zamanlı dosya/indirme/USB/ağ kalkanı, SSE canlı telemetri, CSRF & CSP korumalı yerel yönetim arayüzü (`server.js`, `public/`) |
| **Kurulum & Paketleme** | Node.js + Inno Setup 6 | Tam bağımsız `.exe` portable ZIP ve `Setup.exe` derleme betikleri (`scripts/build-package.js`, `installer/AegisCore.iss`) |

## Kaynaktan Çalıştırma

Proje harici `npm`, `pip` veya `NuGet` paketi **gerektirmez**; yalnızca standart kütüphaneler ve Windows API'leri kullanılır:

- **İşletim Sistemi:** Windows 10 / 11 (64-bit)
- **Node.js:** v18+ (önerilen v20/v24)
- **Python:** 3.10+ (`python` PATH üzerinde)
- **.NET SDK:** 8.0 (`dotnet` PATH üzerinde)

1. Depoyu klonlayın ve proje klasörüne geçin:
   ```powershell
   git clone https://github.com/fkalsasx/AegisCore.git
   cd AegisCore
   ```
2. `Baslat_AegisCore.bat` dosyasını çalıştırın veya manuel başlatın:
   ```powershell
   dotnet build "engines\csharp-scanner\AegisScanner.csproj" -c Release -o "engines\csharp-scanner\bin"
   node --max-old-space-size=192 --expose-gc server.js
   ```

## Kendi `.exe` Paketinizi Derleme

```powershell
# Tam bağımsız Portable ZIP (+ yerel Inno Setup 6 kuruluysa Setup.exe) üretir -> dist/
node scripts/build-package.js

# Node/Python gömmeden hafif paket üretir -> dist/
node scripts/build-package.js --lite
```

## Doğrulama ve Testler

- **AEGIS-VORTEX 6+1 Modül Testi:**
  ```powershell
  python vortex/tests/test_vortex_e2e.py
  ```
- **SuperLX 1.0 Anti-RAT Benchmark (19 Vektör):** Arayüz üzerinden veya `POST /api/pro/superlx-benchmark` uç noktasından çalıştırılabilir.

## Güvenlik ve Gizlilik Notu

Çalışma zamanı klasörleri (`quarantine/`, `AEGIS_Vault/`, `AEGIS_ShadowStore/`, `AEGIS_ShadowCage/`, `licenses/`, `realtime_protected_zone/`) ve şifreleme anahtarları (`.vault_master.key`, `.shadow_master.key`) ilk çalıştırmada yerel makinede otomatik oluşturulur ve `.gitignore` ile sürüm kontrolü dışında tutulur.
