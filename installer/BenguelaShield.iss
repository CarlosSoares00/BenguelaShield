; BenguelaShield - Instalador Inno Setup
; Antivirus Open Source Municipal - Benguela, Angola

[Setup]
AppId={{BENGUELA-SHIELD-2025}
AppName=BenguelaShield
AppVersion=1.0.0
AppVerName=BenguelaShield 1.0.0
AppPublisher=Administracao Municipal de Benguela
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
UninstallDisplayName=BenguelaShield - Desinstalar
UninstallDisplayIcon={app}\BenguelaShield.exe

[Languages]
Name: "brazilianportuguese"; MessagesFile: "compiler:Languages\BrazilianPortuguese.isl"

[Tasks]
Name: "desktopicon"; Description: "Criar atalho no Ambiente de Trabalho"; GroupDescription: "Atalhos:"
Name: "startup"; Description: "Iniciar BenguelaShield com o Windows"; GroupDescription: "Arranque:"

[Files]
; Executavel principal
Source: "..\dist\BenguelaShield\BenguelaShield.exe"; DestDir: "{app}"; Flags: ignoreversion
; Servico Windows
Source: "..\dist\BenguelaShield\BenguelaShieldService.exe"; DestDir: "{app}"; Flags: ignoreversion
; Motor ClamAV — so .exe, .dll e certs
Source: "..\dist\BenguelaShield\engine\*.exe"; DestDir: "{app}\engine"; Flags: ignoreversion
Source: "..\dist\BenguelaShield\engine\*.dll"; DestDir: "{app}\engine"; Flags: ignoreversion
Source: "..\dist\BenguelaShield\engine\certs\*"; DestDir: "{app}\engine\certs"; Flags: ignoreversion recursesubdirs skipifsourcedoesntexist
; Configuracoes
Source: "..\dist\BenguelaShield\config\*"; DestDir: "{app}\config"; Flags: ignoreversion skipifsourcedoesntexist
; Base de assinaturas
Source: "..\dist\BenguelaShield\db\*"; DestDir: "{app}\db"; Flags: ignoreversion skipifsourcedoesntexist
; Runtime PyInstaller (_internal)
Source: "..\dist\BenguelaShield\_internal\*"; DestDir: "{app}\_internal"; Flags: ignoreversion recursesubdirs
; Documentacao
Source: "license_pt.txt"; DestDir: "{app}"; Flags: ignoreversion

[Dirs]
Name: "{app}\quarantine"
Name: "{app}\logs"
Name: "{app}\db"

[Icons]
Name: "{group}\BenguelaShield"; Filename: "{app}\BenguelaShield.exe"
Name: "{group}\Desinstalar BenguelaShield"; Filename: "{uninstallexe}"
Name: "{autodesktop}\BenguelaShield"; Filename: "{app}\BenguelaShield.exe"; Tasks: desktopicon

[Registry]
Root: HKLM; Subkey: "SOFTWARE\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "BenguelaShield"; ValueData: """{app}\BenguelaShield.exe"" --minimized"; Flags: uninsdeletevalue; Tasks: startup
Root: HKLM; Subkey: "SOFTWARE\BenguelaShield"; ValueType: string; ValueName: "InstallPath"; ValueData: "{app}"; Flags: uninsdeletekey
Root: HKLM; Subkey: "SOFTWARE\BenguelaShield"; ValueType: string; ValueName: "Version"; ValueData: "1.0.0"; Flags: uninsdeletekey

[Code]
function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  ResultCode: Integer;
begin
  Result := '';
  // Parar GUI e servico antes de instalar
  Exec(ExpandConstant('{app}\BenguelaShield.exe'), '--kill', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  if FileExists(ExpandConstant('{app}\BenguelaShieldService.exe')) then
  begin
    Exec(ExpandConstant('{app}\BenguelaShieldService.exe'), 'stop', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec(ExpandConstant('{app}\BenguelaShieldService.exe'), 'remove', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  end;
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  ResultCode: Integer;
  AppDir: String;
begin
  if CurStep = ssPostInstall then
  begin
    AppDir := ExpandConstant('{app}');

    // Create freshclam.conf with correct install path
    SaveStringToFile(AppDir + '\config\freshclam.conf',
      'DatabaseDirectory ' + AppDir + '\db' + #13#10 +
      'DatabaseMirror database.clamav.net' + #13#10 +
      'DNSDatabaseInfo current.cvd.clamav.net' + #13#10 +
      'MaxAttempts 3' + #13#10,
      False);

    // Register and start service
    if FileExists(AppDir + '\BenguelaShieldService.exe') then
    begin
      Exec(AppDir + '\BenguelaShieldService.exe', 'install', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
      Exec(AppDir + '\BenguelaShieldService.exe', 'start', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    end;

    // Create ProgramData directories
    CreateDir(ExpandConstant('{commonappdata}\BenguelaShield'), 0);
    CreateDir(ExpandConstant('{commonappdata}\BenguelaShield\logs'), 0);
    CreateDir(ExpandConstant('{commonappdata}\BenguelaShield\quarantine'), 0);
    CreateDir(ExpandConstant('{commonappdata}\BenguelaShield\config'), 0);
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  ResultCode: Integer;
begin
  if CurUninstallStep = usUninstall then
  begin
    // Stop and remove service
    if FileExists(ExpandConstant('{app}\BenguelaShieldService.exe')) then
    begin
      Exec(ExpandConstant('{app}\BenguelaShieldService.exe'), 'stop', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
      Exec(ExpandConstant('{app}\BenguelaShieldService.exe'), 'remove', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    end;
    // Kill GUI
    Exec(ExpandConstant('{app}\BenguelaShield.exe'), '--kill', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  end;
end;

[Run]
Filename: "{app}\BenguelaShield.exe"; Description: "Abrir BenguelaShield"; Flags: nowait postinstall skipifsilent

[UninstallRun]
Filename: "{app}\BenguelaShieldService.exe"; Parameters: "stop"; Flags: runhidden; RunOnceId: "StopService"
Filename: "{app}\BenguelaShieldService.exe"; Parameters: "remove"; Flags: runhidden; RunOnceId: "RemoveService"

[UninstallDelete]
Type: filesandordirs; Name: "{app}\_internal"
Type: filesandordirs; Name: "{app}\engine"
Type: filesandordirs; Name: "{app}\db"
Type: filesandordirs; Name: "{app}\config"
Type: filesandordirs; Name: "{app}\logs"
Type: filesandordirs; Name: "{app}\quarantine"
Type: dirifempty; Name: "{app}"

[Messages]
BeveledLabel=BenguelaShield v1.0.0 - Administracao Municipal de Benguela
WelcomeLabel1=Bem-vindo ao Assistente de Instalacao do [name]
WelcomeLabel2=O BenguelaShield vai ser instalado no seu computador.%n%nAntivirus open source criado para proteger a rede municipal.%n%nRequer Windows 10 (64-bit) ou superior.%n%nClique em Avancar para continuar.
InstallingLabel=Aguarde enquanto o [name] e instalado...
FinishedHeadingLabel=Instalacao Completa
FinishedLabel=O [name] foi instalado com sucesso.%nO servico de proteccao esta ativo.
