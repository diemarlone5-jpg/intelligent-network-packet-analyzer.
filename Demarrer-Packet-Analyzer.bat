@echo off
chcp 65001 >nul
title Intelligent Network Packet Analyzer
cd /d "%~dp0"

echo.
echo   ============================================================
echo     INTELLIGENT NETWORK PACKET ANALYZER
echo   ============================================================
echo.

rem --- Le serveur tourne-t-il deja ? Dans ce cas, on ouvre la page. ---
netstat -ano | findstr /R /C:"127.0.0.1:8000 .*LISTENING" >nul 2>&1
if %errorlevel%==0 (
    echo   Le serveur tourne deja.
    echo   Ouverture de la page dans ton navigateur...
    start "" http://127.0.0.1:8000
    timeout /t 3 >nul
    exit /b 0
)

if not exist ".venv\Scripts\python.exe" (
    echo   [ERREUR] L'environnement Python du projet est introuvable.
    echo            Attendu : .venv\Scripts\python.exe
    echo            Ce fichier doit rester dans le dossier du projet.
    echo.
    pause
    exit /b 1
)

echo   Demarrage du serveur...
echo   La page va s'ouvrir toute seule dans ton navigateur.
echo.
echo   POUR ARRETER L'ANALYSEUR : ferme cette fenetre noire.
echo.
echo   ------------------------------------------------------------
echo.

start "" http://127.0.0.1:8000

".venv\Scripts\python.exe" run.py --port 8000

echo.
echo   ------------------------------------------------------------
echo   Le serveur s'est arrete.
echo.
pause
