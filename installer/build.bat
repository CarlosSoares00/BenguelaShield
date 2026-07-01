@echo off
chcp 65001 >nul
setlocal EnableDelayedExpansion

echo.
echo ====================================================
echo   BENGUELA SHIELD — BUILD COMPLETO v1.0.0
echo   Administracao Municipal de Benguela
echo ====================================================
echo.

:: ─── VERIFICAR PREREQUISITOS ───
echo [1/7] Verificando prerequisitos...

python --version >nul 2>&1
if errorlevel 1 (echo ERRO: Python nao encontrado! & pause & exit /b 1)

pip show pyinstaller >nul 2>&1
if errorlevel 1 (echo A instalar PyInstaller... & pip install pyinstaller --quiet)
echo   Python e PyInstaller OK

:: ─── LIMPAR BUILDS ANTERIORES ───
echo.
echo [2/7] Limpar builds anteriores...
if exist "dist" rmdir /s /q "dist"
if exist "build" rmdir /s /q "build"
echo   OK

:: ─── COMPILAR GUI ───
echo.
echo [3/7] Compilar GUI (BenguelaShield.exe)...
pyinstaller installer\build_gui.spec --noconfirm --clean
if errorlevel 1 (echo ERRO: GUI falhou! & pause & exit /b 1)
echo   OK

:: ─── COMPILAR SERVICO ───
echo.
echo [4/7] Compilar Servico (BenguelaShieldService.exe)...
pyinstaller installer\build_service.spec --noconfirm --clean
if errorlevel 1 (echo ERRO: Servico falhou! & pause & exit /b 1)
echo   OK

:: ─── PREPARAR DIST ───
echo.
echo [5/7] Preparar dist...
if not exist "dist\BenguelaShield" mkdir "dist\BenguelaShield"
if not exist "dist\BenguelaShield\engine" mkdir "dist\BenguelaShield\engine"
if not exist "dist\BenguelaShield\engine\certs" mkdir "dist\BenguelaShield\engine\certs"
if not exist "dist\BenguelaShield\db" mkdir "dist\BenguelaShield\db"
if not exist "dist\BenguelaShield\config" mkdir "dist\BenguelaShield\config"

:: Motor ClamAV — SO .exe e .dll (sem .lib, .pdb, docs)
for %%f in ("engine\clamav\x64\*.exe" "engine\clamav\x64\*.dll") do copy /y "%%f" "dist\BenguelaShield\engine\" >nul 2>nul
xcopy /s /e /y "engine\clamav\x64\certs" "dist\BenguelaShield\engine\certs\" >nul 2>nul

:: Assinaturas — SO .cvd/.cld (sem .sign, sem .dat de dev)
for %%f in ("engine\clamav\db\*.cvd" "engine\clamav\db\*.cld") do copy /y "%%f" "dist\BenguelaShield\db\" >nul 2>nul

:: Servico
copy /y "dist\BenguelaShieldService\BenguelaShieldService.exe" "dist\BenguelaShield\" >nul 2>nul

:: Remover artefactos stale
if exist "dist\BenguelaShield\config\clamd.pid" del /q "dist\BenguelaShield\config\clamd.pid" >nul 2>nul
if exist "dist\BenguelaShield\config\benguelashield.db" del /q "dist\BenguelaShield\config\benguelashield.db" >nul 2>nul
echo   OK — Engine: .exe+.dll+.certs | DB: .cvd/.cld | Sem .lib/.pdb/.docs

:: ─── VERIFICAR CONTEUDO ───
echo.
echo [6/7] Verificar conteudo do dist...
set /a _exe_count=0
set /a _dll_count=0
set /a _cvd_count=0
for %%f in ("dist\BenguelaShield\engine\*.exe") do set /a _exe_count+=1
for %%f in ("dist\BenguelaShield\engine\*.dll") do set /a _dll_count+=1
for %%f in ("dist\BenguelaShield\db\*.cvd" "dist\BenguelaShield\db\*.cld") do set /a _cvd_count+=1
echo   Engine: !_exe_count! .exe, !_dll_count! .dll
echo   Assinaturas: !_cvd_count! ficheiros de base de dados
echo   GUI: BenguelaShield.exe
echo   Servico: BenguelaShieldService.exe

:: Calcular tamanho total
for /f "tokens=3" %%a in ('dir /s /-c "dist\BenguelaShield" 2^>nul ^| findstr /c:"ficheiro(s)"') do set _total_size=%%a
echo   Tamanho total do dist: !_total_size! bytes
echo   OK

:: ─── COMPILAR INSTALADOR ───
echo.
echo [7/7] Compilar instalador (Inno Setup)...
set "ISCC="
if exist "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" set "ISCC=C:\Program Files (x86)\Inno Setup 6\ISCC.exe"
if exist "C:\Program Files\Inno Setup 6\ISCC.exe" set "ISCC=C:\Program Files\Inno Setup 6\ISCC.exe"
if exist "%LOCALAPPDATA%\Programs\Inno Setup 6\ISCC.exe" set "ISCC=%LOCALAPPDATA%\Programs\Inno Setup 6\ISCC.exe"
if "!ISCC!"=="" (echo ERRO: Inno Setup 6 nao encontrado! & echo Descarregue de: https://jrsoftware.org/isinfo.php & pause & exit /b 1)

"!ISCC!" "installer\BenguelaShield.iss"
if errorlevel 1 (echo ERRO: Inno Setup falhou! & pause & exit /b 1)

:: ─── VERIFICAR OUTPUT ───
if not exist "installer\Output\BenguelaShield_Setup_1.0.0.exe" (
    echo ERRO: Ficheiro output nao gerado!
    pause
    exit /b 1
)

for %%f in ("installer\Output\BenguelaShield_Setup_1.0.0.exe") do set _installer_size=%%~zf
set /a _installer_mb=!_installer_size! / 1048576

echo.
echo ====================================================
echo   BUILD COMPLETO COM SUCESSO!
echo.
echo   Instalador: installer\Output\BenguelaShield_Setup_1.0.0.exe
echo   Tamanho: !_installer_mb! MB
echo.
echo   Conteudo incluido:
echo     - BenguelaShield.exe (GUI PyQt6)
echo     - BenguelaShieldService.exe (Servico Windows)
echo     - Motor ClamAV (exe + dll + certs)
echo     - Assinaturas de virus pre-configuradas
echo     - Regras YARA (23 regras)
echo     - Modelo IA (LightGBM)
echo     - Runtime Python 3.12 completo
echo.
echo   Para testar: execute o .exe num PC limpo ou VM
echo ====================================================
pause
