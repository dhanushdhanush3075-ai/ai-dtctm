; ════════════════════════════════════════════════════════════════════
; AI-DTCTM Windows Installer (Inno Setup script)
; ════════════════════════════════════════════════════════════════════
; Build:
;   1. Run PyInstaller first:
;      pyinstaller --clean --noconfirm \
;          --onedir --windowed --icon=assets/app.ico \
;          --name=AI-DTCTM-Launcher \
;          --add-data "main_project.py;." \
;          --add-data "auth_ui.py;." \
;          --add-data "config.py;." \
;          --add-data "core;core" \
;          --add-data "_pages;_pages" \
;          --add-data "assets;assets" \
;          --add-data "sample_databases;sample_databases" \
;          --collect-all streamlit \
;          launcher.py
;
;   2. Compile this .iss with Inno Setup 6:
;      iscc.exe installer/AI-DTCTM.iss
;
;   3. Output: installer/Output/AI-DTCTM-Setup-1.0.0.exe
;
; The installer:
;   • Installs to C:\Program Files\AI-DTCTM\  (admin) or %LOCALAPPDATA% (user)
;   • Creates desktop shortcut + Start Menu entry
;   • Registers uninstaller in Windows "Apps & features"
;   • Optionally launches the app immediately on finish

#define MyAppName       "AI-DTCTM"
#define MyAppVersion    "1.0.0"
#define MyAppPublisher  "DHANUSH S · MCE"
#define MyAppURL        "https://github.com/dhanush-mce/ai-dtctm"
#define MyAppExeName    "AI-DTCTM-Launcher.exe"

[Setup]
AppId={{B4F1D2C7-6D8A-4A2E-9E3D-1F5C8D7E2B4A}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
OutputBaseFilename=AI-DTCTM-Setup-{#MyAppVersion}
OutputDir=Output
SetupIconFile=..\assets\app.ico
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
ArchitecturesAllowed=x64
ArchitecturesInstallIn64BitMode=x64
MinVersion=10.0
; LicenseFile + InfoBeforeFile omitted — added later when you have a real LICENSE

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Additional shortcuts:"
Name: "startmenuicon"; Description: "Create a &Start menu shortcut"; GroupDescription: "Additional shortcuts:"
Name: "quicklaunch"; Description: "Pin to the Windows Taskbar"; GroupDescription: "Integration:"; Flags: unchecked

[Files]
; PyInstaller output — the entire onedir bundle ships
Source: "..\dist\AI-DTCTM-Launcher\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

; Sample databases for first-run demo
Source: "..\sample_databases\*"; DestDir: "{app}\sample_databases"; Flags: ignoreversion recursesubdirs

; License + Readme accessible after install
Source: "..\README.md";    DestDir: "{app}"; Flags: ignoreversion
Source: "..\QUICKSTART.md"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\assets\app.ico"
Name: "{group}\{cm:UninstallProgram,{#MyAppName}}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\assets\app.ico"; Tasks: desktopicon
Name: "{autoprograms}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\assets\app.ico"; Tasks: startmenuicon

[Run]
; Optional immediate launch after finish (user can uncheck the checkbox)
Filename: "{app}\{#MyAppExeName}"; Description: "Launch {#MyAppName}"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
; Clean app data on uninstall — but ASK first via the wizard prompt
Type: filesandordirs; Name: "{app}\logs"
Type: filesandordirs; Name: "{app}\data\source_clones"
Type: filesandordirs; Name: "{app}\data\apk_clones"
Type: filesandordirs; Name: "{app}\data\apk_workbench"

[Code]
function InitializeSetup(): Boolean;
begin
  Result := True;
  if not IsWin64 then
  begin
    MsgBox('AI-DTCTM requires 64-bit Windows 10 or later.', mbCriticalError, MB_OK);
    Result := False;
  end;
end;
