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
WizardStyle=modern
ShowLanguageDialog=yes

[Languages]
Name: "brazilianportuguese"; MessagesFile: "compiler:Languages\BrazilianPortuguese.isl"

[Tasks]
Name: "desktopicon"; Description: "Criar atalho no Ambiente de Trabalho"; GroupDescription: "Atalhos:"
Name: "startup"; Description: "Iniciar BenguelaShield com o Windows"; GroupDescription: "Arranque:"

[Files]
Source: "..\dist\BenguelaShield\BenguelaShield.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\dist\BenguelaShield\BenguelaShieldService.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\dist\BenguelaShield\engine\*"; DestDir: "{app}\engine"; Flags: ignoreversion recursesubdirs
Source: "..\dist\BenguelaShield\modules\*"; DestDir: "{app}\modules"; Flags: ignoreversion recursesubdirs
Source: "..\dist\BenguelaShield\config\*"; DestDir: "{app}\config"; Flags: ignoreversion skipifsourcedoesntexist
Source: "..\README.md"; DestDir: "{app}"; Flags: ignoreversion isreadme
Source: "license_pt.txt"; DestDir: "{app}"; Flags: ignoreversion

[Dirs]
Name: "{app}\quarantine"
Name: "{app}\logs"
Name: "{app}\db"

[Icons]
Name: "{group}\BenguelaShield"; Filename: "{app}\BenguelaShield.exe"
Name: "{group}\Desinstalar"; Filename: "{uninstallexe}"
Name: "{autodesktop}\BenguelaShield"; Filename: "{app}\BenguelaShield.exe"; Tasks: desktopicon

[Registry]
Root: HKLM; Subkey: "SOFTWARE\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "BenguelaShield"; ValueData: """{app}\BenguelaShield.exe"" --minimized"; Flags: uninsdeletevalue; Tasks: startup

[Run]
Filename: "{app}\BenguelaShield.exe"; Description: "Abrir BenguelaShield"; Flags: nowait postinstall skipifsilent

[UninstallRun]
Filename: "{app}\BenguelaShieldService.exe"; Parameters: "stop"; Flags: runhidden
Filename: "{app}\BenguelaShieldService.exe"; Parameters: "remove"; Flags: runhidden

[Messages]
BeveledLabel=BenguelaShield v1.0.0 - Administracao Municipal de Benguela
WelcomeLabel1=Bem-vindo ao Assistente de Instalacao do [name]
WelcomeLabel2=O BenguelaShield vai ser instalado no seu computador.%n%nAntivirus open source criado para proteger a rede municipal.%n%nClique em Avancar para continuar.
ReadyLabel=Pronto para instalar o [name].
InstallingLabel=Aguarde enquanto o [name] e instalado...
FinishedHeadingLabel=Instalacao Completa
FinishedLabel=O [name] foi instalado com sucesso.