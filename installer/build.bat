@echo off
chcp 65001 >nul
setlocal EnableDelayedExpansion

echo.
echo ====================================================
echo   BENGUELA SHIELD - BUILD v1.0.0
echo ====================================================
echo.

:: Clean
echo [1/6] Limpar builds anteriores...
if exist "dist" rmdir /s /q "dist"
if exist "build" rmdir /s /q "build"
echo   OK

:: Build GUI
echo.
echo [2/6] Compilar GUI...
pyinstaller installer\build_gui.spec --noconfirm --clean
if errorlevel 1 (echo ERRO: GUI falhou! & pause & exit /b 1)
echo   OK

:: Build Service
echo.
echo [3/6] Compilar Servico...
pyinstaller installer\build_service.spec --noconfirm --clean
if errorlevel 1 (echo ERRO: Servico falhou! & pause & exit /b 1)
echo   OK

:: Prepare dist
echo.
echo [4/6] Preparar dist...
if not exist "dist\BenguelaShield\engine" mkdir "dist\BenguelaShield\engine"
if not exist "dist\BenguelaShield\config" mkdir "dist\BenguelaShield\config"
if not exist "dist\BenguelaShield\db" mkdir "dist\BenguelaShield\db"
if not exist "dist\BenguelaShield\engine\certs" mkdir "dist\BenguelaShield\engine\certs"

:: Copy ClamAV binaries + DLLs + certs
copy /y "engine\clamav\x64\*.exe" "dist\BenguelaShield\engine\" >nul
copy /y "engine\clamav\x64\*.dll" "dist\BenguelaShield\engine\" >nul
xcopy /s /e /y "engine\clamav\x64\certs" "dist\BenguelaShield\engine\certs\" >nul

:: Copy configs
copy /y "config\clamd_runtime.conf" "dist\BenguelaShield\config\" >nul 2>nul
copy /y "config\freshclam.conf" "dist\BenguelaShield\config\" >nul 2>nul
copy /y "engine\clamav\x64\freshclam.conf" "dist\BenguelaShield\config\" >nul 2>nul

:: Copy DB
copy /y "engine\clamav\db\*.cvd" "dist\BenguelaShield\db\" >nul 2>nul
copy /y "engine\clamav\db\freshclam.dat" "dist\BenguelaShield\db\" >nul 2>nul

:: Copy service
copy /y "dist\BenguelaShieldService\BenguelaShieldService.exe" "dist\BenguelaShield\" >nul
echo   OK

:: Create freshclam.conf for install path
echo.
echo [5/6] Criar freshclam.conf...
echo DatabaseDirectory {app}\db > "_freshclam_template.conf"
echo DatabaseMirror database.clamav.net >> "_freshclam_template.conf"
echo DNSDatabaseInfo current.cvd.clamav.net >> "_freshclam_template.conf"
echo MaxAttempts 3 >> "_freshclam_template.conf"
echo   OK

:: Build installer
echo.
echo [6/6] Compilar instalador...
"C:\Users\carlo\AppData\Local\Programs\Inno Setup 6\ISCC.exe" "installer\BenguelaShield.iss"
if errorlevel 1 (echo ERRO: Inno Setup falhou! & pause & exit /b 1)

echo.
echo ====================================================
echo   BUILD COMPLETO!
echo   installer\Output\BenguelaShield_Setup_1.0.0.exe
echo ====================================================
pause
