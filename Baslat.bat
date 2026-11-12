@echo off
chcp 65001 >nul
title SafeBox - wsb-triage
cd /d "%~dp0"
set URL=http://127.0.0.1:8765

rem Panel already running? Just open it.
curl -s -o nul -m 2 %URL%/api/system-status && (
    echo Panel zaten calisiyor, tarayici aciliyor: %URL%
    start "" %URL%
    exit /b 0
)

where python >nul 2>&1 || (
    echo [HATA] Python bulunamadi. https://www.python.org adresinden Python 3.10+ kurun
    echo        ^(kurulumda "Add python.exe to PATH" kutusunu isaretleyin^).
    pause
    exit /b 1
)

python -c "import fastapi, uvicorn, pefile, requests, multipart" >nul 2>&1 || (
    echo [HATA] Gerekli Python paketleri eksik. Su komutu calistirin, sonra bu dosyayi tekrar acin:
    echo.
    echo     pip install -r requirements.txt
    echo.
    pause
    exit /b 1
)

echo ====================================================================
echo   SafeBox Analiz Merkezi baslatiliyor...  %URL%
echo   Kapatmak icin bu pencereyi kapatin.
echo ====================================================================

rem Open the browser only once the server answers (max ~20 s).
start "" /b powershell -NoProfile -WindowStyle Hidden -Command "for($i=0;$i -lt 40;$i++){try{Invoke-WebRequest -UseBasicParsing '%URL%/api/system-status' -TimeoutSec 1 | Out-Null; Start-Process '%URL%'; break}catch{Start-Sleep -Milliseconds 500}}"

python app.py
if errorlevel 1 (
    echo.
    echo [HATA] Sunucu durdu. Yukaridaki mesaja bakin. 8765 portunu baska bir program kullaniyor olabilir.
    pause
)
