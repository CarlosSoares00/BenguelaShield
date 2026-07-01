@echo off
chcp 65001 >nul
echo.
echo  ====================================================
echo   BENGUELA SHIELD — Empacotar Portatil
echo  ====================================================
echo.

set "SRC=%~dp0.."
set "OUT=%~dp0BenguelaShield_Portatil"
set "PY=C:\Users\carlo\AppData\Local\Programs\Python\Python312"

:: Limpar
if exist "%OUT%" rmdir /s /q "%OUT%"
mkdir "%OUT%"

:: Copiar codigo fonte
echo A copiar codigo fonte...
xcopy /s /e /y /q "%SRC%\modules" "%OUT%\modules\" >nul
xcopy /s /e /y /q "%SRC%\gui" "%OUT%\gui\" >nul
xcopy /s /e /y /q "%SRC%\services" "%OUT%\services\" >nul
xcopy /s /e /y /q "%SRC%\engine\clamav\x64\*.exe" "%OUT%\engine\clamav\x64\" >nul 2>nul
xcopy /s /e /y /q "%SRC%\engine\clamav\x64\*.dll" "%OUT%\engine\clamav\x64\" >nul 2>nul
xcopy /s /e /y /q "%SRC%\engine\clamav\x64\certs" "%OUT%\engine\clamav\x64\certs\" >nul 2>nul
xcopy /s /e /y /q "%SRC%\engine\clamav\db\*.cvd" "%OUT%\engine\clamav\db\" >nul 2>nul
xcopy /s /e /y /q "%SRC%\engine\clamav\db\freshclam.dat" "%OUT%\engine\clamav\db\" >nul 2>nul
xcopy /s /e /y /q "%SRC%\config" "%OUT%\config\" >nul 2>nul
xcopy /s /e /y /q "%SRC%\tests" "%OUT%\tests\" >nul 2>nul

:: Copiar ficheiros raiz
copy /y "%SRC%\main_gui.py" "%OUT%\" >nul
copy /y "%SRC%\main.py" "%OUT%\" >nul
copy /y "%SRC%\run_service.py" "%OUT%\" >nul
copy /y "%SRC%\requirements.txt" "%OUT%\" >nul
copy /y "%SRC%\setup_info.py" "%OUT%\" >nul
copy /y "%SRC%\__init__.py" "%OUT%\" >nul 2>nul
copy /y "%SRC%\README.md" "%OUT%\" >nul

:: Copiar launcher
copy /y "%~dp0iniciar.bat" "%OUT%\" >nul

:: Copiar Python embeddable (portatil)
echo A preparar Python portatil...
if not exist "%OUT%\python" (
    mkdir "%OUT%\python"
    powershell -Command "Invoke-WebRequest -Uri 'https://www.python.org/ftp/python/3.12.10/python-3.12.10-embed-amd64.zip' -OutFile '%TEMP%\python-embed.zip'" 2>nul
    powershell -Command "Expand-Archive -Path '%TEMP%\python-embed.zip' -DestinationPath '%OUT%\python' -Force" 2>nul
    del /q "%TEMP%\python-embed.zip" >nul 2>nul
)

:: Criar script de setup para Python embeddable
(
echo import subprocess, sys, os
echo.
echo # Instalar pip no Python embeddable
echo pyez = os.path.join^("python", "python312._pth"^)
echo if os.path.exists^(pyez^):
echo     with open^(pyez, "r"^) as f: content = f.read^(^)
echo     if "#import site" in content:
echo         content = content.replace^("#import site", "import site"^)
echo         with open^(pyez, "w"^) as f: f.write^(content^)
echo.
echo # Descarregar pip
echo import urllib.request
echo pip_url = "https://bootstrap.pypa.io/get-pip.py"
echo urllib.request.urlretrieve^(pip_url, "python/get-pip.py"^)
echo os.system^("python\\python.exe python\\get-pip.py --quiet"^)
echo.
echo # Instalar dependencias
echo os.system^("python\\python.exe -m pip install -r requirements.txt --quiet"^)
echo print^("Dependencias instaladas!"^)
echo.
echo os.system^("python\\python.exe main_gui.py"^)
) > "%OUT%\instalar_e_correr.py"

echo.
echo  ====================================================
echo   PACOTE PORTATIL CRIADO!
echo.
echo   Pasta: %OUT%
echo.
echo   Para distribuir:
echo     1. Comprimir a pasta em .zip
echo     2. Copiar para o PC de teste
echo     3. Extrair e executar iniciar.bat
echo  ====================================================
echo.
pause
