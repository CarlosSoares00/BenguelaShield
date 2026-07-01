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

:: Copy ClamAV binaries + DLLs + certs (excluir .lib, .pdb, docs)
for %%f in ("engine\clamav\x64\*.exe" "engine\clamav\x64\*.dll") do copy /y "%%f" "dist\BenguelaShield\engine\" >nul
xcopy /s /e /y "engine\clamav\x64\certs" "dist\BenguelaShield\engine\certs\" >nul

:: Copy configs (NO copy clamd_runtime.conf — generated at install time)
if not exist "dist\BenguelaShield\config" mkdir "dist\BenguelaShield\config"

:: Copy DB
copy /y "engine\clamav\db\*.cvd" "dist\BenguelaShield\db\" >nul 2>nul
copy /y "engine\clamav\db\freshclam.dat" "dist\BenguelaShield\db\" >nul 2>nul

:: Copy service
copy /y "dist\BenguelaShieldService\BenguelaShieldService.exe" "dist\BenguelaShield\" >nul
echo   OK

:: Remove stale artifacts
if exist "dist\BenguelaShield\config\clamd.pid" del /q "dist\BenguelaShield\config\clamd.pid" >nul 2>nul
if exist "dist\BenguelaShield\config\benguelashield.db" del /q "dist\BenguelaShield\config\benguelashield.db" >nul 2>nul
if exist "_freshclam_template.conf" del /q "_freshclam_template.conf" >nul
echo   OK

:: Build installer
echo.
echo [5/5] Compilar instalador...
set "ISCC="
if exist "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" set "ISCC=C:\Program Files (x86)\Inno Setup 6\ISCC.exe"
if exist "C:\Program Files\Inno Setup 6\ISCC.exe" set "ISCC=C:\Program Files\Inno Setup 6\ISCC.exe"
if exist "C:\Users\carlo\AppData\Local\Programs\Inno Setup 6\ISCC.exe" set "ISCC=C:\Users\carlo\AppData\Local\Programs\Inno Setup 6\ISCC.exe"
if "%ISCC%"=="" (echo ERRO: Inno Setup nao encontrado! & pause & exit /b 1)
"%ISCC%" "installer\BenguelaShield.iss"
if errorlevel 1 (echo ERRO: Inno Setup falhou! & pause & exit /b 1)

echo.
echo ====================================================
echo   BUILD COMPLETO!
echo   installer\Output\BenguelaShield_Setup_1.0.0.exe
echo ====================================================
pause
