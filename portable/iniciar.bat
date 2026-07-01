@echo off
chcp 65001 >nul 2>&1
title BenguelaShield
set "DIR=%~dp0"

echo.
echo  =========================================
echo   BENGUELA SHIELD v1.0.0
echo   Administracao Municipal de Benguela
echo  =========================================
echo.

python --version >nul 2>&1
if errorlevel 1 (
    echo [!] Python nao encontrado.
    echo     Instale: winget install Python.Python.3.12
    echo     Ou: https://www.python.org/downloads/
    pause
    exit /b 1
)

python -c "import PyQt6, psutil, watchdog" >nul 2>&1
if errorlevel 1 (
    echo [i] Instalando dependencias...
    pip install -r "%DIR%requirements.txt" --quiet --disable-pip-version-check 2>nul
    pip install PyQt6 psutil watchdog yara-python pycryptodome pywin32 lightgbm numpy scikit-learn requests --quiet --disable-pip-version-check 2>nul
    echo [OK] Dependencias instaladas
)

if not exist "%DIR%logs" mkdir "%DIR%logs"
if not exist "%DIR%quarantine" mkdir "%DIR%quarantine"

echo [i] Iniciando BenguelaShield...
start "" python "%DIR%main_gui.py"
echo.
echo  =========================================
echo   BenguelaShield iniciado!
echo  =========================================
echo.
