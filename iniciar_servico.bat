@echo off
REM BenguelaShield — Iniciar serviço como processo normal
REM Executar como Administrador

cd /d C:\Users\carlo\antivirus\BenguelaShield
echo ============================================
echo   BenguelaShield — Serviço em execução
echo   Para parar: Ctrl+C
echo ============================================
python run_service.py
pause
