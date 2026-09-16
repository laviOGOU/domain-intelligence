@echo off
REM Domain Intelligence — lance l'application web.
REM Double-clique sur ce fichier (la fenetre doit rester ouverte).
cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
    echo Creation de l'environnement virtuel...
    py -m venv .venv
    .venv\Scripts\python.exe -m pip install --upgrade pip
    .venv\Scripts\python.exe -m pip install -r requirements.txt
)

echo.
echo   Application : http://127.0.0.1:5001
echo   (ferme cette fenetre pour arreter le serveur)
echo.
.venv\Scripts\python.exe app.py
pause
