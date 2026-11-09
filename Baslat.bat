@echo off
chcp 65001 >nul
title SafeBox - Zararli Yazilim ve Sandbox Analiz Merkezi
cd /d "%~dp0"
echo ====================================================================
echo   SafeBox Analiz Merkezi Baslatiliyor...
echo   Tarayicinizda http://127.0.0.1:8765 adresi otomatik acilacaktir.
echo ====================================================================
start "" "http://127.0.0.1:8765"
python app.py
pause
