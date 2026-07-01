; ═══════════════════════════════════════════════════════════════
; BenguelaShield v1.0.0 — Instalador Profissional
; Antivirus Open Source Municipal — Benguela, Angola
; ═══════════════════════════════════════════════════════════════

[Setup]
AppId={{BENGUELA-SHIELD-2025-ANTIVIRUS}
AppName=BenguelaShield
AppVersion=1.0.0
AppVerName=BenguelaShield 1.0.0
AppPublisher=Administracao Municipal de Benguela
AppPublisherURL=https://github.com/CarlosSoares00/BenguelaShield
DefaultDirName={autopf}\BenguelaShield
DefaultGroupName=BenguelaShield
LicenseFile=license_pt.txt
InfoBeforeFile=info_before.txt
InfoAfterFile=info_after.txt
OutputDir=Output
OutputBaseFilename=BenguelaShield_Setup_1.0.0
SetupIconFile=assets\icon.ico
UninstallIconFile=assets\icon.ico
Compression=lzma2/ultra64
SolidCompression=yes
PrivilegesRequired=admin
PrivilegesRequiredOverridesAllowed=dialog
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0.17763
WizardStyle=modern
WizardSizePercent=110
ShowLanguageDialog=yes
CloseApplications=yes
RestartApplications=no
SetupLogging=yes
UninstallDisplayName=BenguelaShield - Antivirus Open Source
UninstallDisplayIcon={app}\BenguelaShield.exe

[Languages]
Name: "brazilianportuguese"; MessagesFile: "compiler:Languages\BrazilianPortuguese.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: checkedonce
Name: "startup"; Description: "Iniciar BenguelaShield com o Windows"; GroupDescription: "Arranque automatico:"; Flags: checkedonce
Name: "updatedefinitions"; Description: "Actualizar assinaturas de virus apos instalacao"; GroupDescription: "Pos-instalacao:"; Flags: checkedonce

[Files]
; Executavel principal (GUI)
Source: "..\dist\BenguelaShield\BenguelaShield.exe"; DestDir: "{app}"; Flags: ignoreversion
; Servico Windows
Source: "..\dist\BenguelaShield\BenguelaShieldService.exe"; DestDir: "{app}"; Flags: ignoreversion
; Motor ClamAV — apenas .exe, .dll e certs
Source: "..\dist\BenguelaShield\engine\*.exe"; DestDir: "{app}\engine"; Flags: ignoreversion
Source: "..\dist\BenguelaShield\engine\*.dll"; DestDir: "{app}\engine"; Flags: ignoreversion
Source: "..\dist\BenguelaShield\engine\certs\*"; DestDir: "{app}\engine\certs"; Flags: ignoreversion recursesubdirs skipifsourcedoesntexist
; Base de assinaturas (pre-definidas)
Source: "..\dist\BenguelaShield\db\*"; DestDir: "{app}\db"; Flags: ignoreversion skipifsourcedoesntexist
; Runtime PyInstaller (_internal)
Source: "..\dist\BenguelaShield\_internal\*"; DestDir: "{app}\_internal"; Flags: ignoreversion recursesubdirs
; Documentacao
Source: "license_pt.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\README.md"; DestDir: "{app}"; Flags: ignoreversion isreadme

[Dirs]
Name: "{app}\quarantine"
Name: "{app}\logs"
Name: "{app}\db"
Name: "{commonappdata}\BenguelaShield"
Name: "{commonappdata}\BenguelaShield\logs"
Name: "{commonappdata}\BenguelaShield\quarantine"
Name: "{commonappdata}\BenguelaShield\config"

[Icons]
; Menu Iniciar
Name: "{group}\BenguelaShield"; Filename: "{app}\BenguelaShield.exe"; Comment: "Abrir BenguelaShield"
Name: "{group}\{cm:UninstallProgram,BenguelaShield}"; Filename: "{uninstallexe}"
; Ambiente de Trabalho
Name: "{autodesktop}\BenguelaShield"; Filename: "{app}\BenguelaShield.exe"; Tasks: desktopicon

[Registry]
; Arranque automatico
Root: HKLM; Subkey: "SOFTWARE\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "BenguelaShield"; ValueData: """{app}\BenguelaShield.exe"" --minimized"; Flags: uninsdeletevalue; Tasks: startup
; Informacoes de instalacao
Root: HKLM; Subkey: "SOFTWARE\BenguelaShield"; ValueType: string; ValueName: "InstallPath"; ValueData: "{app}"; Flags: uninsdeletekey
Root: HKLM; Subkey: "SOFTWARE\BenguelaShield"; ValueType: string; ValueName: "Version"; ValueData: "1.0.0"; Flags: uninsdeletekey
Root: HKLM; Subkey: "SOFTWARE\BenguelaShield"; ValueType: string; ValueName: "Publisher"; ValueData: "Administracao Municipal de Benguela"; Flags: uninsdeletekey

[Code]
// ═══════════════════════════════════════════════════════════════
// Verificacoes antes da instalacao
// ═══════════════════════════════════════════════════════════════

function IsWindows10OrLater: Boolean;
var
  Version: TWindowsVersion;
begin
  GetWindowsVersionEx(Version);
  Result := (Version.Major >= 10);
end;

function HasEnoughDiskSpace: Boolean;
var
  FreeSpace: Int64;
begin
  FreeSpace := DiskFree(0);
  Result := (FreeSpace > 500 * 1024 * 1024); // 500 MB
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  ResultCode: Integer;
  MsgResult: Integer;
begin
  Result := '';

  // Verificar Windows 10+
  if not IsWindows10OrLater then
  begin
    Result := 'O BenguelaShield requer Windows 10 (versao 1809) ou superior.';
    Exit;
  end;

  // Verificar espaco em disco
  if not HasEnoughDiskSpace then
  begin
    Result := 'Espaco em disco insuficiente. Necessario: 500 MB minimo.';
    Exit;
  end;

  // Terminar GUI existente
  Exec(ExpandConstant('{app}\BenguelaShield.exe'), '--kill', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);

  // Parar e remover servico existente
  if FileExists(ExpandConstant('{app}\BenguelaShieldService.exe')) then
  begin
    Exec(ExpandConstant('{app}\BenguelaShieldService.exe'), 'stop', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec(ExpandConstant('{app}\BenguelaShieldService.exe'), 'remove', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  end;

  // Aguardar ficheiros libertados
  Sleep(2000);
end;

// ═══════════════════════════════════════════════════════════════
// Pos-instalacao — configurar tudo
// ═══════════════════════════════════════════════════════════════

procedure CurStepChanged(CurStep: TSetupStep);
var
  ResultCode: Integer;
  AppDir: String;
  DataDir: String;
  FreshClamConf: String;
  ClamdConf: String;
begin
  if CurStep = ssPostInstall then
  begin
    AppDir := ExpandConstant('{app}');
    DataDir := ExpandConstant('{commonappdata}\BenguelaShield');

    // 1. Criar freshclam.conf
    FreshClamConf := AppDir + '\config\freshclam.conf';
    SaveStringToFile(FreshClamConf,
      '# BenguelaShield - FreshClam Configuration' + #13#10 +
      'DatabaseDirectory ' + AppDir + '\db' + #13#10 +
      'DatabaseMirror database.clamav.net' + #13#10 +
      'DNSDatabaseInfo current.cvd.clamav.net' + #13#10 +
      'MaxAttempts 3' + #13#10 +
      'NotifyDatabaseUpdate yes' + #13#10,
      False);

    // 2. Criar clamd.conf (gerado em runtime pelo servico, mas criar um basico)
    ClamdConf := AppDir + '\config\clamd_runtime.conf';
    SaveStringToFile(ClamdConf,
      '# BenguelaShield - clamd configuration' + #13#10 +
      'TCPSocket 3310' + #13#10 +
      'TCPAddr 127.0.0.1' + #13#10 +
      'MaxThreads 4' + #13#10 +
      'DatabaseDirectory ' + AppDir + '\db' + #13#10 +
      'LogFile ' + DataDir + '\logs\clamd.log' + #13#10 +
      'LogTime yes' + #13#10 +
      'PidFile ' + DataDir + '\config\clamd.pid' + #13#10 +
      'Foreground yes' + #13#10 +
      'YaraRulesDir ' + AppDir + '\_internal\modules\yara_engine\rules\benguelashield' + #13#10,
      False);

    // 3. Copiar assinaturas para ProgramData (se ainda nao existirem)
    if not DirExists(DataDir + '\db') then
    begin
      CreateDir(DataDir + '\db', 0);
      FileCopy(AppDir + '\db\main.cvd', DataDir + '\db\main.cvd', False);
      FileCopy(AppDir + '\db\daily.cld', DataDir + '\db\daily.cld', False);
      FileCopy(AppDir + '\db\bytecode.cvd', DataDir + '\db\bytecode.cvd', False);
    end;

    // 4. Registar e iniciar servico Windows
    if FileExists(AppDir + '\BenguelaShieldService.exe') then
    begin
      Exec(AppDir + '\BenguelaShieldService.exe', 'install', '', SW_SHOW, ewWaitUntilTerminated, ResultCode);
      if ResultCode = 0 then
        Exec(AppDir + '\BenguelaShieldService.exe', 'start', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    end;

    // 5. Actualizar assinaturas (se tarefa selecionada)
    if IsTaskSelected('updatedefinitions') then
    begin
      if FileExists(AppDir + '\engine\freshclam.exe') then
      begin
        Exec(AppDir + '\engine\freshclam.exe',
          '--config-file=' + FreshClamConf,
          '', SW_SHOW, ewWaitUntilTerminated, ResultCode);
      end;
    end;
  end;
end;

// ═══════════════════════════════════════════════════════════════
// Desinstalacao — limpar tudo
// ═══════════════════════════════════════════════════════════════

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  ResultCode: Integer;
begin
  if CurUninstallStep = usUninstall then
  begin
    // Parar e remover servico
    if FileExists(ExpandConstant('{app}\BenguelaShieldService.exe')) then
    begin
      Exec(ExpandConstant('{app}\BenguelaShieldService.exe'), 'stop', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
      Exec(ExpandConstant('{app}\BenguelaShieldService.exe'), 'remove', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    end;
    // Terminar GUI
    Exec(ExpandConstant('{app}\BenguelaShield.exe'), '--kill', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    // Aguardar
    Sleep(1000);
    // Remover registry
    RegDeleteValue(HKLM, 'SOFTWARE\Microsoft\Windows\CurrentVersion\Run', 'BenguelaShield');
    RegDeleteKeyIncludingSubkeys(HKLM, 'SOFTWARE\BenguelaShield');
  end;
end;

// ═══════════════════════════════════════════════════════════════
// Perguntar se mantem dados ao desinstalar
// ═══════════════════════════════════════════════════════════════

function InitializeUninstall: Boolean;
begin
  Result := True;
end;

// ═══════════════════════════════════════════════════════════════
// Pos-Instalacao — Abrir aplicacao
// ═══════════════════════════════════════════════════════════════

[Run]
Filename: "{app}\BenguelaShield.exe"; Description: "Abrir BenguelaShield agora"; Flags: nowait postinstall skipifsilent skipifnotsilent

[UninstallRun]
Filename: "{app}\BenguelaShieldService.exe"; Parameters: "stop"; Flags: runhidden; RunOnceId: "StopBS"
Filename: "{app}\BenguelaShieldService.exe"; Parameters: "remove"; Flags: runhidden; RunOnceId: "RemoveBS"

[UninstallDelete]
Type: filesandordirs; Name: "{app}\_internal"
Type: filesandordirs; Name: "{app}\engine"
Type: filesandordirs; Name: "{app}\db"
Type: filesandordirs; Name: "{app}\config"
Type: dirifempty; Name: "{app}"
Type: filesandordirs; Name: "{commonappdata}\BenguelaShield\logs"
Type: filesandordirs; Name: "{commonappdata}\BenguelaShield\config"
Type: dirifempty; Name: "{commonappdata}\BenguelaShield"

[Messages]
; Portuguese customizations
BeveledLabel=BenguelaShield v1.0.0 — Administracao Municipal de Benguela
WelcomeLabel1=Bem-vindo ao Assistente de Instalacao do BenguelaShield
WelcomeLabel2=BenguelaShield e um antiviro open source para Windows.%n%nInclui tres motores de deteccao:%n  • ClamAV (3.6M assinaturas)%n  • YARA (23 regras)%n  • IA LightGBM (analise comportamental)%n%nRequer Windows 10 64-bit (versao 1809+)%nEspaco necessario: 500 MB%n%nClique em Avancar para continuar.
DirLabel=Escolha a pasta de instalacao do BenguelaShield:
ReadyLabel=Pronto para instalar o BenguelaShield no seu computador.%n%nClique em Instalar para comecar.
FinishedHeadingLabel=Instalacao Concluida com Sucesso!
FinishedLabel=BenguelaShield foi instalado correctamente.%n%nO servico de proteccao em tempo real esta activo.%nAs assinaturas de virus estao pre-configuradas.%n%nClique em Concluir para fechar o assistente.
