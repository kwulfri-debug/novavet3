@echo off
cd /d "%~dp0"
echo Iniciando servidor novaVet con base de datos SQLite...
start "" http://127.0.0.1:8000
python server.py
pause
