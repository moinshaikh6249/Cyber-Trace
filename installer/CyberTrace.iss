; =========================================================
; CyberTrace — Digital Forensics Investigation System
; Professional Windows Installer Script (Inno Setup 6)
; =========================================================

#define MyAppName "CyberTrace"
#define MyAppVersion "1.0.0"
#define MyAppPublisher "CyberTrace"
#define MyAppURL "https://cybertrace.local"
#define MyAppExeName "CyberTrace.exe"
#define SourcePayloadDir "D:\CyberTrace\dist\CyberTrace"

[Setup]
; Unique App ID for Windows Install / Uninstall registry tracking
AppId={{D37E8C94-67A1-4F28-8422-9B7C3E1F9A2B}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={autopf}\{#MyAppName}
UninstallDisplayIcon={app}\{#MyAppExeName}
UninstallDisplayName={#MyAppName}
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
DefaultGroupName={#MyAppName}
; Allow non-admin user installs (installs to LocalAppData\Programs\CyberTrace)
; or admin installs (installs to Program Files\CyberTrace)
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
OutputDir=D:\CyberTrace\installer\Output
OutputBaseFilename=CyberTrace_Setup
SetupIconFile=D:\CyberTrace\assets\cybertrace.ico
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
; Complete PyInstaller onedir application payload
Source: "{#SourcePayloadDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\_internal\assets\cybertrace.ico"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\_internal\assets\cybertrace.ico"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent
