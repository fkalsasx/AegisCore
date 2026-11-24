@echo off
cd /d "%~dp0"
title AegisCore Endpoint Security
echo ============================================================================
echo   AEGISCORE ENDPOINT SECURITY v5.0 (POLYGLOT ENGINE)
echo   C# .NET 8 Native + Python 3.10 Heuristic + Node.js Real-Time Shield
echo ============================================================================
echo.
if not exist "engines\csharp-scanner\bin\AegisScanner.exe" (
    echo [1/2] C# .NET 8 Native Motoru derleniyor...
    dotnet build "engines\csharp-scanner\AegisScanner.csproj" -c Release -o "engines\csharp-scanner\bin"
)
echo [2/2] AegisCore Cekirdek Servisi ve Masaustu Penceresi baslatiliyor...
start "" /b node --max-old-space-size=192 --expose-gc server.js
timeout /t 2 /nobreak >nul
if exist "%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe" (
    start "" "%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe" --app=http://localhost:4880 --window-size=1280,860
) else if exist "%ProgramFiles%\Microsoft\Edge\Application\msedge.exe" (
    start "" "%ProgramFiles%\Microsoft\Edge\Application\msedge.exe" --app=http://localhost:4880 --window-size=1280,860
) else if exist "%ProgramFiles%\Google\Chrome\Application\chrome.exe" (
    start "" "%ProgramFiles%\Google\Chrome\Application\chrome.exe" --app=http://localhost:4880 --window-size=1280,860
) else (
    start http://localhost:4880
)
