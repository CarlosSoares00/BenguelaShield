; BenguelaShield v1.0.0 - Instalador Inno Setup
; Antivirus Open Source - Administracao Municipal de Benguela

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
Compression=lzma2/ultra64
SolidCompression=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0.17763
WizardStyle=modern
ShowLanguageDialog=yes
CloseApplications=yes
RestartApplications=no
SetupLogging=yes
UninstallDisplayName=BenguelaShield - Antivirus Open Source
UninstallDisplayIcon={app}\BenguelaShield.exe

[Languages]
Name: "portugues"; MessagesFile: "compiler:Languages\BrazilianPortuguese.isl"

[Tasks]
Name: "desktopicon"; Description: "Criar atalho no Ambiente de Trabalho"; GroupDescription: "Atalhos:"
Name: "startup"; Description: "Iniciar BenguelaShield com o Windows"; GroupDescription: "Arranque:"
Name: "updatedefinitions"; Description: "Actualizar assinaturas de virus apos instalacao"; GroupDescription: "Pos-instalacao:"

[Files]
Source: "..\dist\BenguelaShield\BenguelaShield.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\dist\BenguelaShield\BenguelaShieldService.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\dist\BenguelaShield\engine\*.exe"; DestDir: "{app}\engine"; Flags: ignoreversion
Source: "..\dist\BenguelaShield\engine\*.dll"; DestDir: "{app}\engine"; Flags: ignoreversion
Source: "..\dist\BenguelaShield\engine\certs\*"; DestDir: "{app}\engine\certs"; Flags: ignoreversion recursesubdirs skipifsourcedoesntexist
Source: "..\dist\BenguelaShield\db\*"; DestDir: "{app}\db"; Flags: ignoreversion skipifsourcedoesntexist
Source: "..\dist\BenguelaShield\_internal\*"; DestDir: "{app}\_internal"; Flags: ignoreversion recursesubdirs
Source: "license_pt.txt"; DestDir: "{app}"; Flags: ignoreversion

[Dirs]
Name: "{app}\quarantine"
Name: "{app}\logs"
Name: "{app}\db"
Name: "{commonappdata}\BenguelaShield"
Name: "{commonappdata}\BenguelaShield\logs"
Name: "{commonappdata}\BenguelaShield\quarantine"
Name: "{commonappdata}\BenguelaShield\config"

[Icons]
Name: "{group}\BenguelaShield"; Filename: "{app}\BenguelaShield.exe"
Name: "{group}\Desinstalar BenguelaShield"; Filename: "{uninstallexe}"
Name: "{autodesktop}\BenguelaShield"; Filename: "{app}\BenguelaShield.exe"; Tasks: desktopicon

[Registry]
Root: HKLM; Subkey: "SOFTWARE\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "BenguelaShield"; ValueData: """{app}\BenguelaShield.exe"" --minimized"; Flags: uninsdeletevalue; Tasks: startup; Check: IsAdminInstallMode
Root: HKLM; Subkey: "SOFTWARE\BenguelaShield"; ValueType: string; ValueName: "InstallPath"; ValueData: "{app}"; Flags: uninsdeletekey; Check: IsAdminInstallMode
Root: HKLM; Subkey: "SOFTWARE\BenguelaShield"; ValueType: string; ValueName: "Version"; ValueData: "1.0.0"; Flags: uninsdeletekey; Check: IsAdminInstallMode

[Code]
function IsWindows10OrLater: Boolean;
var
  Version: TWindowsVersion;
begin
  GetWindowsVersionEx(Version);
  Result := (Version.Major >= 10);
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  ResultCode: Integer;
begin
  Result := '';
  if not IsWindows10OrLater then
  begin
    Result := 'O BenguelaShield requer Windows 10 (versao 1809) ou superior.';
    Exit;
  end;
  Exec(ExpandConstant('{app}\BenguelaShield.exe'), '--kill', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  if FileExists(ExpandConstant('{app}\BenguelaShieldService.exe')) then
  begin
    Exec(ExpandConstant('{app}\BenguelaShieldService.exe'), 'stop', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec(ExpandConstant('{app}\BenguelaShieldService.exe'), 'remove', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  end;
  Sleep(2000);
end;

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

    FreshClamConf := AppDir + '\config\freshclam.conf';
    SaveStringToFile(FreshClamConf,
      'DatabaseDirectory ' + AppDir + '\db' + #13#10 +
      'DatabaseMirror database.clamav.net' + #13#10 +
      'DNSDatabaseInfo current.cvd.clamav.net' + #13#10 +
      'MaxAttempts 3' + #13#10, False);

    ClamdConf := AppDir + '\config\clamd_runtime.conf';
    SaveStringToFile(ClamdConf,
      'TCPSocket 3310' + #13#10 +
      'TCPAddr 127.0.0.1' + #13#10 +
      'MaxThreads 4' + #13#10 +
      'DatabaseDirectory ' + AppDir + '\db' + #13#10 +
      'LogFile ' + DataDir + '\logs\clamd.log' + #13#10 +
      'LogTime yes' + #13#10 +
      'PidFile ' + DataDir + '\config\clamd.pid' + #13#10 +
      'Foreground yes' + #13#10, False);

    if not DirExists(DataDir + '\db') then
    begin
      CreateDir(DataDir + '\db');
      CopyFile(AppDir + '\db\main.cvd', DataDir + '\db\main.cvd', False);
      CopyFile(AppDir + '\db\daily.cld', DataDir + '\db\daily.cld', False);
      CopyFile(AppDir + '\db\bytecode.cvd', DataDir + '\db\bytecode.cvd', False);
    end;

    if FileExists(AppDir + '\BenguelaShieldService.exe') then
    begin
      Exec(AppDir + '\BenguelaShieldService.exe', 'install', '', SW_SHOW, ewWaitUntilTerminated, ResultCode);
      if ResultCode = 0 then
        Exec(AppDir + '\BenguelaShieldService.exe', 'start', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    end;

    if WizardIsTaskSelected('updatedefinitions') then
    begin
      if FileExists(AppDir + '\engine\freshclam.exe') then
        Exec(AppDir + '\engine\freshclam.exe', '--config-file=' + FreshClamConf, '', SW_SHOW, ewWaitUntilTerminated, ResultCode);
    end;
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  ResultCode: Integer;
begin
  if CurUninstallStep = usUninstall then
  begin
    if FileExists(ExpandConstant('{app}\BenguelaShieldService.exe')) then
    begin
      Exec(ExpandConstant('{app}\BenguelaShieldService.exe'), 'stop', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
      Exec(ExpandConstant('{app}\BenguelaShieldService.exe'), 'remove', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    end;
    Exec(ExpandConstant('{app}\BenguelaShield.exe'), '--kill', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Sleep(1000);
  end;
end;

function InitializeUninstall: Boolean;
begin
  Result := True;
end;

[Run]
Filename: "{app}\BenguelaShield.exe"; Description: "Abrir BenguelaShield agora"; Flags: nowait postinstall skipifsilent

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
