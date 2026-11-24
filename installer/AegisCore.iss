; AegisCore Endpoint Security - Inno Setup 6 Installer Script
#ifndef MyAppVersion
  #define MyAppVersion "6.0.0"
#endif
#ifndef SourceDir
  #define SourceDir "..\dist\AegisCore-v6.0.0-win-x64"
#endif
#ifndef OutputDir
  #define OutputDir "..\dist"
#endif

#define MyAppName "AegisCore Endpoint Security"
#define MyAppPublisher "AegisCore Security"
#define MyAppURL "https://github.com/fkalsasx/AegisCore"
#define MyAppExeName "AegisCore.exe"

[Setup]
AppId={{8E4C7A91-3D52-4F8B-A19E-7C2F5D90B4A1}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} v{#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}/issues
AppUpdatesURL={#MyAppURL}/releases
DefaultDirName={localappdata}\Programs\AegisCore
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
AppMutex=Local\AegisCore_EndpointSecurity_v6
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir={#OutputDir}
OutputBaseFilename=AegisCore-v{#MyAppVersion}-Setup
SetupIconFile=..\launcher\aegis.ico
UninstallDisplayIcon={app}\{#MyAppExeName}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
CloseApplications=yes

[Languages]
Name: "turkish"; MessagesFile: "compiler:Languages\Turkish.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"
Name: "startupicon"; Description: "Windows açılışında sistem tepsisinde otomatik başlat"; GroupDescription: "Başlangıç Seçenekleri:"; Flags: unchecked

[Files]
Source: "{#SourceDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\{#MyAppExeName}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\{#MyAppExeName}"; Tasks: desktopicon
Name: "{userstartup}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Parameters: "--startup"; IconFilename: "{app}\{#MyAppExeName}"; Tasks: startupicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent
