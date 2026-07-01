@echo off
cd /d C:\Users\carlo\antivirus\BenguelaShield
set PYTHONPATH=C:\Users\carlo\antivirus\BenguelaShield
python "%~dp0benguelashield_service.py" %*
