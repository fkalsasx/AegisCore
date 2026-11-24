# AegisCore Endpoint Security (SuperLX 1.0 & AEGIS-VORTEX)

Windows için geliştirilmiş, sıfır harici bağımlılıklı (zero third-party dependency), çok katmanlı (polyglot) uç nokta güvenlik ve gerçek zamanlı tehdit koruma platformu.

## Mimari Katmanlar

| Katman | Teknoloji | Görev |
| :--- | :--- | :--- |
| **Native Tarama & Ağ Çekirdeği** | C# (.NET 8) | Çok çekirdekli dosya/disk tarama, PE yapısal analiz, Authenticode & Windows Security Catalog doğrulaması, çekirdek TCP/UDP-PID ağ izleme (`engines/csharp-scanner/`) |
| **Sezgisel & Anti-RAT Motoru** | Python 3.10+ (`SuperLX 1.0`) | Gelişmiş betik/PE/entropi analizi, obfuscation & Base64/GZip çözümleme, LOLBin / RAT / Defender bypass tespiti (`engines/superlx/`, `engines/python-heuristics/`) |
| **AEGIS-VORTEX Davranış Daemon'ı** | Python 3.10+ + Win32 API | 6+1 modüllü canlı süreç soy ağacı, Canary fidye tuzağı, Gölge Kafes mikro-sandbox, Risk Barometresi, Atomik Zaman Makinesi (LIFO rollback) ve AES-256-GCM kasa (`vortex/`) |
| **Orkestratör & Web Paneli** | Node.js + Vanilla HTML/CSS/JS | Gerçek zamanlı dosya/indirme/USB/ağ kalkanı, SSE canlı telemetri, CSRF & CSP korumalı yerel yönetim arayüzü (`server.js`, `public/`) |
| **Opsiyonel Native Modüller** | C++20 & Rust | Deneysel yerel çekirdek & hızlı PE/fuzzy-hash bileşenleri (`vortex/native_cpp/`, `vortex/rust_engine/`) |

## Gereksinimler

Proje harici `npm`, `pip` veya `NuGet` paketi **gerektirmez**; yalnızca standart kütüphaneler ve Windows API'leri kullanılır:

- **İşletim Sistemi:** Windows 10 / 11 (64-bit)
- **Node.js:** v18+ (önerilen v20/v24)
- **Python:** 3.10+ (`python` PATH üzerinde)
- **.NET SDK:** 8.0 (`dotnet` PATH üzerinde)

## Hızlı Başlangıç

1. Depoyu klonlayın ve proje klasörüne geçin:
   ```powershell
   git clone https://github.com/fkalsasx/Aeriscore.git
   cd Aeriscore
   ```
2. `Baslat_AegisCore.bat` dosyasını çalıştırın:
   - İlk çalıştırmada C# .NET 8 tarama motoru (`AegisScanner.exe`) otomatik olarak Release modunda derlenir.
   - `server.js` düşük bellek sınırıyla başlatılır ve arayüz `http://localhost:4880` adresinde açılır.

### Manuel Çalıştırma

```powershell
dotnet build "engines\csharp-scanner\AegisScanner.csproj" -c Release -o "engines\csharp-scanner\bin"
node --max-old-space-size=192 --expose-gc server.js
```

## Doğrulama ve Testler

- **AEGIS-VORTEX 6+1 Modül Testi:**
  ```powershell
  python vortex/tests/test_vortex_e2e.py
  ```
- **SuperLX 1.0 Anti-RAT Benchmark (19 Vektör):** Arayüz üzerinden veya `POST /api/pro/superlx-benchmark` uç noktasından çalıştırılabilir.

## Güvenlik ve Gizlilik Notu

Çalışma zamanı klasörleri (`quarantine/`, `AEGIS_Vault/`, `AEGIS_ShadowStore/`, `AEGIS_ShadowCage/`, `licenses/`, `realtime_protected_zone/`) ve şifreleme anahtarları (`.vault_master.key`, `.shadow_master.key`) ilk çalıştırmada yerel makinede otomatik oluşturulur ve `.gitignore` ile sürüm kontrolü dışında tutulur.
