@echo off
title NetPulse IPAM - Serveur Web & Scanner Reseau Local
cd /d "%~dp0"
echo Demarrage du serveur NetPulse IPAM sur http://localhost:8080 ...
start "" http://localhost:8080
python app.py 8080
pause
