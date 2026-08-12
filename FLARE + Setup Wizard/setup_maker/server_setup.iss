; ═════════════════════════════════════════════════════════════════════════════
;  FLARE Server — Inno Setup installer script
;  Compile:  ISCC.exe server_setup.iss
;  Output:   Output\FLARE_Server_Setup.exe
; ═════════════════════════════════════════════════════════════════════════════

#define AppName      "FLARE Server"
#define AppPublisher "FLARE Security"
#define AppId        "{{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}"
#define SvcName      "FLAREServer"

[Setup]
AppId={#AppId}
AppName={#AppName}
AppVerName={#AppName}
AppPublisher={#AppPublisher}
AppSupportURL=https://github.com/your-org/flare
DefaultDirName={autopf}\FLARE\Server
DefaultGroupName=FLARE
DirExistsWarning=no
AllowNoIcons=yes
OutputDir=Output
OutputBaseFilename=FLARE_Server_Setup
WizardImageFile=banner.bmp
WizardSmallImageFile=small.bmp
WizardStyle=modern
Compression=lzma2/ultra64
SolidCompression=yes
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
CloseApplications=yes
UninstallDisplayName={#AppName}
UninstallDisplayIcon={app}\flare_server.py
SetupLogging=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

; ─── Files ────────────────────────────────────────────────────────────────────

[Files]
Source: "..\server\flare_server.py";    DestDir: "{app}"; Flags: ignoreversion
Source: "..\server\generate_pki.py";    DestDir: "{app}"; Flags: ignoreversion
Source: "..\server\generate_cert.py";   DestDir: "{app}"; Flags: ignoreversion
Source: "..\server\requirements_server.txt"; DestDir: "{app}"; Flags: ignoreversion

Source: "..\server\proto\log_schema_pb2.py"; DestDir: "{app}\proto"; Flags: ignoreversion
Source: "..\server\proto\__init__.py";       DestDir: "{app}\proto"; Flags: ignoreversion

Source: "..\server\engine\flare_agent.py";             DestDir: "{app}\engine";              Flags: ignoreversion
Source: "..\server\engine\host\host_engine.py";        DestDir: "{app}\engine\host";         Flags: ignoreversion
Source: "..\server\engine\host\ioc_loader.py";         DestDir: "{app}\engine\host";         Flags: ignoreversion
Source: "..\server\engine\host\rules.py";              DestDir: "{app}\engine\host";         Flags: ignoreversion
Source: "..\server\engine\host\__init__.py";           DestDir: "{app}\engine\host";         Flags: ignoreversion
Source: "..\server\engine\ioc\ioc_domains.txt";        DestDir: "{app}\engine\ioc";          Flags: ignoreversion
Source: "..\server\engine\ioc\ioc_ips.txt";            DestDir: "{app}\engine\ioc";          Flags: ignoreversion
Source: "..\server\engine\ioc\ioc_process_chains.txt"; DestDir: "{app}\engine\ioc";          Flags: ignoreversion
Source: "..\server\engine\ioc\ioc_process_names.txt";  DestDir: "{app}\engine\ioc";          Flags: ignoreversion
Source: "..\server\engine\network\models\network_mlp_weights.json"; DestDir: "{app}\engine\network\models"; Flags: ignoreversion

Source: "..\server\ui\index.html"; DestDir: "{app}\ui"; Flags: ignoreversion
Source: "..\server\ui\flare_logo.png"; DestDir: "{app}\ui"; Flags: ignoreversion

[Dirs]
Name: "{app}\logs";  Permissions: everyone-full
Name: "{app}\data";  Permissions: everyone-full
Name: "{app}\certs"; Permissions: everyone-full

[Icons]
Name: "{group}\FLARE Server";           Filename: "{code:GetPythonPath}"; Parameters: """{app}\flare_server.py"""; WorkingDir: "{app}"; Comment: "Open FLARE Server manager"
Name: "{group}\Uninstall FLARE Server"; Filename: "{uninstallexe}"
Name: "{commondesktop}\FLARE Server";   Filename: "{code:GetPythonPath}"; Parameters: """{app}\flare_server.py"""; WorkingDir: "{app}"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Additional icons:"

[Run]
Filename: "{code:GetPythonPath}"; Parameters: "-m pip install --no-input -q -r ""{app}\requirements_server.txt"""; \
    StatusMsg: "Installing Python packages (this may take a few minutes)..."; \
    Flags: runhidden waituntilterminated

Filename: "{code:GetPythonPath}"; \
    Parameters: "-c ""import sys,glob,subprocess; s=[p for p in glob.glob(sys.prefix+chr(47)+'Scripts'+chr(47)+'pywin32_postinstall.py') if __import__('os').path.exists(p)]; subprocess.call([sys.executable,s[0],'-install']) if s else None"""; \
    StatusMsg: "Configuring pywin32..."; Flags: runhidden waituntilterminated

Filename: "{code:GetPythonPath}"; Parameters: """{app}\generate_pki.py"""; WorkingDir: "{app}"; \
    StatusMsg: "Generating TLS certificates..."; Flags: runhidden waituntilterminated

Filename: "powershell"; \
    Parameters: "-NoProfile -ExecutionPolicy Bypass -Command ""Import-Certificate -FilePath '{app}\certs\ca.crt' -CertStoreLocation Cert:\LocalMachine\Root -EA SilentlyContinue | Out-Null"""; \
    StatusMsg: "Installing CA certificate into Windows trust store..."; \
    Flags: runhidden waituntilterminated

Filename: "powershell"; \
    Parameters: "-NoProfile -ExecutionPolicy Bypass -Command ""if (-not (Get-NetFirewallRule -DisplayName 'FLARE-Server-{code:GetPort}' -EA SilentlyContinue)) {{ New-NetFirewallRule -DisplayName 'FLARE-Server-{code:GetPort}' -Direction Inbound -Protocol TCP -LocalPort {code:GetPort} -Action Allow | Out-Null }}"""; \
    StatusMsg: "Configuring Windows Firewall..."; Flags: runhidden waituntilterminated

Filename: "{cmd}"; Parameters: "/k ""{app}\run_server.bat"""; WorkingDir: "{app}"; \
    Description: "Launch FLARE Server now (interactive menu)"; Flags: nowait postinstall skipifsilent unchecked

[UninstallRun]
Filename: "{code:GetPythonPath}"; Parameters: """{app}\flare_server.py"" stop";   Flags: runhidden waituntilterminated; RunOnceId: "SvcStop"
Filename: "{code:GetPythonPath}"; Parameters: """{app}\flare_server.py"" remove"; Flags: runhidden waituntilterminated; RunOnceId: "SvcRemove"
Filename: "powershell"; Parameters: "-NoProfile -ExecutionPolicy Bypass -Command ""Remove-NetFirewallRule -DisplayName 'FLARE-Server-*' -EA SilentlyContinue"""; \
    Flags: runhidden waituntilterminated; RunOnceId: "FWRemove"
Filename: "powershell"; Parameters: "-NoProfile -ExecutionPolicy Bypass -Command ""Get-ChildItem Cert:\LocalMachine\Root | Where-Object {{ $_.Subject -match 'CN=FLARE CA' }} | ForEach-Object {{ Remove-Item ('Cert:\LocalMachine\Root\' + $_.Thumbprint) -EA SilentlyContinue }}"""; \
    Flags: runhidden waituntilterminated; RunOnceId: "CARemove"

[UninstallDelete]
Type: filesandordirs; Name: "{app}"

; ═════════════════════════════════════════════════════════════════════════════
;  Pascal code
; ═════════════════════════════════════════════════════════════════════════════

[Code]

// ─── Already-installed check ─────────────────────────────────────────────────

function InitializeSetup: Boolean;
var
  UninstStr:      String;
  UninstKey:      String;
  HasUninstaller: Boolean;
  AlreadyHere:    Boolean;
  Choice:         Integer;
  ResultCode:     Integer;
  InstallDir:     String;
begin
  Result := True;

  InstallDir := ExpandConstant('{autopf}') + '\FLARE\Server';
  UninstKey  := 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\' +
                '{#AppId}' + '_is1';

  HasUninstaller := RegQueryStringValue(HKLM,   UninstKey, 'UninstallString', UninstStr) or
                    RegQueryStringValue(HKLM64, UninstKey, 'UninstallString', UninstStr);

  AlreadyHere := HasUninstaller or FileExists(InstallDir + '\flare_server.py');

  if not AlreadyHere then Exit;

  Choice := MsgBox(
    'FLARE Server is already installed on this machine.' + #13#10 + #13#10 +
    'Setup will not continue over an existing installation.' + #13#10 + #13#10 +
    'YES  - Uninstall existing FLARE Server now.' + #13#10 +
    '       Then re-run this setup for a fresh install.' + #13#10 + #13#10 +
    'NO   - Close this dialog and keep the current installation.',
    mbConfirmation, MB_YESNO);

  if Choice = IDYES then begin
    if HasUninstaller then
      Exec(RemoveQuotes(UninstStr), '/NORESTART', '', SW_SHOW,
           ewWaitUntilTerminated, ResultCode)
    else
      Exec('control', 'appwiz.cpl', '', SW_SHOW, ewNoWait, ResultCode);
  end;

  Result := False;
end;


// ─── State ───────────────────────────────────────────────────────────────────
var
  PagePythonWarn:  TWizardPage;
  PageCreds:       TInputQueryWizardPage;
  PageNetwork:     TInputQueryWizardPage;

  GUsername:  String;
  GPassword:  String;
  GPort:      String;
  GPassHash:  String;
  GMinCli:    String;
  GPythonExe: String;   // full path to python.exe, found at wizard start


// ─── Helpers ─────────────────────────────────────────────────────────────────

function RunCapture(Cmd: String; var Output: String): Integer;
var
  TmpFile: String;
  ResultCode: Integer;
  RawOut: AnsiString;
begin
  TmpFile := ExpandConstant('{tmp}\flare_cap.txt');
  // Delete first so a command that prints nothing yields empty output, never
  // stale content from a previous RunCapture call.
  DeleteFile(TmpFile);
  Exec(ExpandConstant('{cmd}'), '/C ' + Cmd + ' > "' + TmpFile + '" 2>&1',
       '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Output := '';
  if FileExists(TmpFile) then begin
    LoadStringFromFile(TmpFile, RawOut);
    Output := String(RawOut);
  end;
  Output := Trim(Output);
  Result := ResultCode;
end;

function FindPythonExe: String;
var
  Output, ExePath: String;
  SubKeys: TArrayOfString;
  WherLines: TStringList;
  i, v: Integer;
begin
  Result := 'python';

  // 1. where.exe — check each result, skip WindowsApps stubs (Store redirects
  //    that don't execute from elevated/redirected contexts)
  RunCapture('where python', Output);
  WherLines := TStringList.Create;
  WherLines.Text := Output;
  for i := 0 to WherLines.Count - 1 do begin
    ExePath := Trim(WherLines[i]);
    if (ExePath <> '') and
       (Pos('WindowsApps', ExePath) = 0) and
       FileExists(ExePath) then begin
      WherLines.Free;
      Result := ExePath;
      Exit;
    end;
  end;
  WherLines.Free;

  if RegGetSubkeyNames(HKCU, 'SOFTWARE\Python\PythonCore', SubKeys) then begin
    for i := GetArrayLength(SubKeys) - 1 downto 0 do begin
      if RegQueryStringValue(HKCU,
           'SOFTWARE\Python\PythonCore\' + SubKeys[i] + '\InstallPath',
           'ExecutablePath', ExePath) then
        if FileExists(ExePath) then begin Result := ExePath; Exit; end;
    end;
  end;

  if RegGetSubkeyNames(HKLM, 'SOFTWARE\Python\PythonCore', SubKeys) then begin
    for i := GetArrayLength(SubKeys) - 1 downto 0 do begin
      if RegQueryStringValue(HKLM,
           'SOFTWARE\Python\PythonCore\' + SubKeys[i] + '\InstallPath',
           'ExecutablePath', ExePath) then
        if FileExists(ExePath) then begin Result := ExePath; Exit; end;
    end;
  end;

  // 4. Glob all user profiles — elevated process can read other users' AppData.
  //    Covers python.org default (Programs\Python\Python3x) and other layouts
  //    (e.g. AppData\Local\Python\bin\python.exe).
  RunCapture('powershell -NoProfile -Command ' +
    '"(Get-ChildItem ' +
    '''C:\Users\*\AppData\Local\Programs\Python\Python3*\python.exe'',' +
    '''C:\Users\*\AppData\Local\Python\*\python.exe''' +
    ' -ErrorAction SilentlyContinue' +
    ' | Where-Object { $_.FullName -notlike ''*WindowsApps*'' }' +
    ' | Select-Object -First 1 -ExpandProperty FullName)"',
    Output);
  Output := Trim(Output);
  if (Output <> '') and FileExists(Output) then begin Result := Output; Exit; end;

  // 5. Check standard per-machine install paths
  for v := 13 downto 10 do begin
    for i := 9 downto 0 do begin
      ExePath := 'C:\Python3' + IntToStr(v) + IntToStr(i) + '\python.exe';
      if FileExists(ExePath) then begin Result := ExePath; Exit; end;
    end;
  end;
end;

function GetPythonPath(Param: String): String;
begin
  Result := GPythonExe;
end;

function PythonOK: Boolean;
var Output: String;
begin
  // If FindPythonExe resolved a real path, trust it — don't try to exec in
  // the elevated context where the user PATH is stripped.
  if GPythonExe <> 'python' then begin
    Result := FileExists(GPythonExe);
    Exit;
  end;
  Result := RunCapture('"' + GPythonExe + '" --version', Output) = 0;
end;

// True only if S is exactly 64 lowercase-hex chars (a SHA-256 digest)
function IsValidSha256(S: String): Boolean;
var
  i: Integer;
  c: Char;
begin
  Result := False;
  if Length(S) <> 64 then Exit;
  for i := 1 to 64 do begin
    c := S[i];
    if not (((c >= '0') and (c <= '9')) or
            ((c >= 'a') and (c <= 'f')) or
            ((c >= 'A') and (c <= 'F'))) then Exit;
  end;
  Result := True;
end;

function HashPassword(Pw: String): String;
var
  Script, ScriptPath, OutPath: String;
  Raw: AnsiString;
  ResultCode: Integer;
begin
  Result := '';
  ScriptPath := ExpandConstant('{tmp}\flare_hash.py');
  OutPath    := ExpandConstant('{tmp}\flare_hash.out');

  // Script writes the digest to a DEDICATED file — never to the shared
  // RunCapture temp file — so a silent python no-op can't leave stale content.
  Script :=
    'import hashlib, sys' + #10 +
    'with open(sys.argv[2], "w") as f:' + #10 +
    '    f.write(hashlib.sha256(sys.argv[1].encode()).hexdigest())';
  SaveStringToFile(ScriptPath, Script, False);

  DeleteFile(OutPath);   // ensure no stale digest from a previous attempt
  Exec(GPythonExe, '"' + ScriptPath + '" "' + Pw + '" "' + OutPath + '"',
       '', SW_HIDE, ewWaitUntilTerminated, ResultCode);

  if FileExists(OutPath) then begin
    LoadStringFromFile(OutPath, Raw);
    Result := Trim(String(Raw));
  end;

  DeleteFile(ScriptPath);
  DeleteFile(OutPath);

  // Reject anything that is not a real SHA-256 digest
  if not IsValidSha256(Result) then
    Result := '';
end;

function WriteServerEnv(InstallDir, User, Hash, Port, MinCli: String): Boolean;
var
  Lines: TStringList;
  DataDir: String;
begin
  // server reads server.env from ROOT/data/server.env (ROOT = __file__.parent)
  DataDir := InstallDir + '\data';
  ForceDirectories(DataDir);
  Lines := TStringList.Create;
  try
    Lines.Add('# FLARE Server Configuration - written by installer');
    Lines.Add('FLARE_DASHBOARD_USER='      + User);
    Lines.Add('FLARE_DASHBOARD_PASS_HASH=' + Hash);
    Lines.Add('FLARE_PORT='               + Port);
    Lines.Add('FLARE_DB_PATH=data\flare.db');
    Lines.Add('FLARE_FL_MIN_CLIENTS='     + MinCli);
    Lines.Add('FLARE_FL_TEST_MODE=0');
    Lines.Add('FLARE_CERT_FILE=certs\server.crt');
    Lines.Add('FLARE_KEY_FILE=certs\server.key');
    Lines.Add('FLARE_CA_CERT=certs\ca.crt');
    Lines.SaveToFile(DataDir + '\server.env');
    Result := True;
  except
    Result := False;
  end;
  Lines.Free;
end;


// ---------------------------------------------------------------------------
// Dark theme — recolour the standard wizard pages to match the FLARE dashboard
// (server/ui/index.html). Colours are Inno BGR ($00BBGGRR).
// ---------------------------------------------------------------------------
const
  CLR_BG     = $270e0a;   // #0A0E27  navy background
  CLR_BG2    = $3a1f1a;   // #1A1F3A  surface / inputs
  CLR_TEXT   = $ede6e0;   // #E0E6ED  body text
  CLR_MUTED  = $a69288;   // #8892A6  secondary text
  CLR_TEAL   = $c4cd4e;   // #4ECDC4  accent
  CLR_ORANGE = $356bff;   // #FF6B35  brand / headings
  CLR_GREEN  = $1ac452;   // #52C41A  success

// Recolour a single control. Labels already painted with a brand accent
// (orange / teal / green / muted) are left untouched so custom-page styling
// survives the generic walk.
procedure ThemeOne(C: TControl);
begin
  if C is TLabel then begin
    if (TLabel(C).Font.Color <> CLR_ORANGE) and (TLabel(C).Font.Color <> CLR_TEAL)
       and (TLabel(C).Font.Color <> CLR_GREEN) and (TLabel(C).Font.Color <> CLR_MUTED) then
      TLabel(C).Font.Color := CLR_TEXT;
  end
  else if C is TNewStaticText then TNewStaticText(C).Font.Color := CLR_TEXT
  else if C is TPanel then begin
    TPanel(C).Color := CLR_BG; TPanel(C).Font.Color := CLR_TEXT;
  end
  else if C is TMemo then begin
    TMemo(C).Color := CLR_BG2; TMemo(C).Font.Color := CLR_TEXT;
  end
  else if C is TNewMemo then begin
    TNewMemo(C).Color := CLR_BG2; TNewMemo(C).Font.Color := CLR_TEXT;
  end
  else if C is TNewEdit then begin
    TNewEdit(C).Color := CLR_BG2; TNewEdit(C).Font.Color := CLR_TEXT;
  end
  else if C is TNewCheckListBox then begin
    TNewCheckListBox(C).Color := CLR_BG2; TNewCheckListBox(C).Font.Color := CLR_TEXT;
  end
  else if C is TNewListBox then begin
    TNewListBox(C).Color := CLR_BG2; TNewListBox(C).Font.Color := CLR_TEXT;
  end
  else if C is TNewCheckBox then begin
    TNewCheckBox(C).Color := CLR_BG; TNewCheckBox(C).Font.Color := CLR_TEXT;
  end
  else if C is TNewRadioButton then begin
    TNewRadioButton(C).Color := CLR_BG; TNewRadioButton(C).Font.Color := CLR_TEXT;
  end
  else if C is TBitmapImage then TBitmapImage(C).BackColor := CLR_BG
  else if C is TNewNotebookPage then TNewNotebookPage(C).Color := CLR_BG;
end;

procedure ThemeWalk(Parent: TWinControl);
var
  i: Integer;
begin
  for i := 0 to Parent.ControlCount - 1 do begin
    ThemeOne(Parent.Controls[i]);
    if Parent.Controls[i] is TWinControl then
      ThemeWalk(TWinControl(Parent.Controls[i]));
  end;
end;

procedure ApplyDarkTheme;
begin
  WizardForm.Color               := CLR_BG;
  WizardForm.MainPanel.Color     := CLR_BG;
  WizardForm.InnerPage.Color     := CLR_BG;
  WizardForm.WelcomePage.Color   := CLR_BG;
  WizardForm.Bevel.Visible       := False;
  WizardForm.Bevel1.Visible      := False;

  ThemeWalk(WizardForm);

  // Header strip + welcome/finish headings get brand accents (after the walk
  // so they win over the generic body-text colour).
  WizardForm.PageNameLabel.Font.Color        := CLR_TEAL;
  WizardForm.PageDescriptionLabel.Font.Color := CLR_MUTED;
  WizardForm.WelcomeLabel1.Font.Color        := CLR_ORANGE;
  WizardForm.WelcomeLabel2.Font.Color        := CLR_TEXT;
  WizardForm.FinishedHeadingLabel.Font.Color := CLR_ORANGE;
  WizardForm.FinishedLabel.Font.Color        := CLR_TEXT;
end;

procedure CurPageChanged(CurPageID: Integer);
begin
  // Re-assert the dark theme on every page (some controls are created lazily).
  ApplyDarkTheme;
end;

// ---------------------------------------------------------------------------

procedure InitializeWizard;
var
  Lbl: TLabel;
  Bevel: TBevel;
  Memo: TMemo;

begin
  GPythonExe := FindPythonExe;

  // ── Python-required warning page ──────────────────────────────────────────
  PagePythonWarn := CreateCustomPage(wpWelcome,
    'Before You Begin - Required Prerequisite',
    'FLARE requires Python 3.10 or later.');

  Bevel := TBevel.Create(PagePythonWarn);
  Bevel.Parent := PagePythonWarn.Surface;
  Bevel.SetBounds(0, 0, PagePythonWarn.SurfaceWidth, 4);
  Bevel.Style := bsLowered;

  Lbl := TLabel.Create(PagePythonWarn);
  Lbl.Parent   := PagePythonWarn.Surface;
  Lbl.SetBounds(0, 14, PagePythonWarn.SurfaceWidth, 28);
  Lbl.Caption  := 'WARNING: Python 3.10+ is NOT bundled and must be installed first.';
  Lbl.WordWrap := True;
  Lbl.Font.Size  := 11;
  Lbl.Font.Style := [fsBold];
  Lbl.Font.Color := $356bff;

  Memo := TMemo.Create(PagePythonWarn);
  Memo.Parent   := PagePythonWarn.Surface;
  Memo.SetBounds(0, 52, PagePythonWarn.SurfaceWidth, 200);
  Memo.ReadOnly := True;
  Memo.ScrollBars := ssVertical;
  Memo.Color := $3a1f1a;
  Memo.Font.Color := $ede6e0;
  Memo.Font.Size  := 10;
  Memo.Lines.Add('HOW TO INSTALL PYTHON:');
  Memo.Lines.Add('');
  Memo.Lines.Add('  1. Go to  https://python.org/downloads');
  Memo.Lines.Add('  2. Download Python 3.10 or later (3.12 recommended).');
  Memo.Lines.Add('  3. Run the installer.');
  Memo.Lines.Add('     !! IMPORTANT: tick "Add Python to PATH"');
  Memo.Lines.Add('        before clicking Install Now.');
  Memo.Lines.Add('  4. Click "Close" once it finishes.');
  Memo.Lines.Add('  5. Re-run this installer.');
  Memo.Lines.Add('');
  Memo.Lines.Add('If Python is already installed but this warning still shows,');
  Memo.Lines.Add('open a new Command Prompt and run:');
  Memo.Lines.Add('');
  Memo.Lines.Add('    python --version');
  Memo.Lines.Add('');
  Memo.Lines.Add('If that fails, Python is not on your PATH.');

  Lbl := TLabel.Create(PagePythonWarn);
  Lbl.Parent  := PagePythonWarn.Surface;
  Lbl.SetBounds(0, 262, PagePythonWarn.SurfaceWidth, 18);
  Lbl.Caption := 'You may continue the installer now if Python is already installed.';
  Lbl.Font.Size  := 9;
  Lbl.Font.Color := $a69288;

  // ── Dashboard credentials page ────────────────────────────────────────────
  PageCreds := CreateInputQueryPage(PagePythonWarn.ID,
    'Dashboard Login',
    'Create the administrator account for the FLARE web dashboard.',
    '');

  PageCreds.Add('Username:', False);
  PageCreds.Add('Password:', True);
  PageCreds.Add('Confirm password:', True);
  PageCreds.Values[0] := 'admin';

  // ── Network / port settings page ─────────────────────────────────────────
  PageNetwork := CreateInputQueryPage(PageCreds.ID,
    'Server Network Settings',
    'Configure the port FLARE agents will connect to.',
    '');

  PageNetwork.Add('Listen port  (agents and dashboard):', False);
  PageNetwork.Add('Min. agents before FL aggregation runs:', False);
  PageNetwork.Values[0] := '7331';
  PageNetwork.Values[1] := '1';

  // Paint the whole wizard dark now that every custom page exists.
  ApplyDarkTheme;
end;


// ─── Page validation ─────────────────────────────────────────────────────────

function NextButtonClick(CurPageID: Integer): Boolean;
var
  Ver, Err: String;
begin
  Result := True;

  // Python warning page — hard block if Python missing
  if CurPageID = PagePythonWarn.ID then begin
    if not PythonOK then begin
      MsgBox(
        'Python was not found on this machine.' + #13#10 + #13#10 +
        'Please install Python 3.10 or later from  https://python.org/downloads' + #13#10 +
        'Make sure to tick "Add Python to PATH" during install.' + #13#10 + #13#10 +
        'Then re-run this installer.',
        mbCriticalError, MB_OK);
      Result := False;
      Exit;
    end;
  end;

  // Credentials page
  if CurPageID = PageCreds.ID then begin
    Err := '';
    if Trim(PageCreds.Values[0]) = '' then
      Err := 'Username cannot be empty.'
    else if Length(PageCreds.Values[1]) < 6 then
      Err := 'Password must be at least 6 characters.'
    else if PageCreds.Values[1] <> PageCreds.Values[2] then
      Err := 'Passwords do not match.';

    if Err <> '' then begin
      MsgBox(Err, mbError, MB_OK);
      Result := False;
      Exit;
    end;

    GUsername := Trim(PageCreds.Values[0]);
    GPassword := PageCreds.Values[1];
    GPassHash := HashPassword(GPassword);

    if GPassHash = '' then begin
      MsgBox(
        'Could not generate a valid password hash.' + #13#10 + #13#10 +
        'Python ran but did not return a usable SHA-256 digest.' + #13#10 +
        'Detected Python: ' + GPythonExe + #13#10 + #13#10 +
        'This usually means the detected Python is a Microsoft Store stub' + #13#10 +
        'or is not functioning. Install Python 3.10+ from python.org' + #13#10 +
        '(tick "Add Python to PATH"), then re-run this installer.',
        mbCriticalError, MB_OK);
      Result := False;
      Exit;
    end;
  end;

  // Port settings page
  if CurPageID = PageNetwork.ID then begin
    GPort   := Trim(PageNetwork.Values[0]);
    GMinCli := Trim(PageNetwork.Values[1]);

    if (StrToIntDef(GPort, 0) < 1) or (StrToIntDef(GPort, 0) > 65535) then begin
      MsgBox('Port must be a number between 1 and 65535.', mbError, MB_OK);
      Result := False;
      Exit;
    end;
    if StrToIntDef(GMinCli, 0) < 1 then begin
      MsgBox('Minimum clients must be 1 or more.', mbError, MB_OK);
      Result := False;
      Exit;
    end;
  end;
end;

// Needed for {code:GetPort} in the firewall [Run] step
function GetPort(Param: String): String;
begin
  if GPort = '' then Result := '7331' else Result := GPort;
end;


// ─── Post-install: write server.env + run_server.bat ────────────────────────

procedure CurStepChanged(CurStep: TSetupStep);
var
  Bat: TStringList;
  AppDir: String;
begin
  if CurStep = ssPostInstall then begin
    if GPassHash = '' then GPassHash := HashPassword('flare');
    if GPort     = '' then GPort     := '7331';
    if GUsername = '' then GUsername := 'admin';
    if GMinCli   = '' then GMinCli   := '1';
    AppDir := ExpandConstant('{app}');
    WriteServerEnv(AppDir, GUsername, GPassHash, GPort, GMinCli);

    // Write a launcher batch so the postinstall "Run now" entry has no quoting issues
    Bat := TStringList.Create;
    try
      Bat.Add('@echo off');
      Bat.Add('"' + GPythonExe + '" "' + AppDir + '\flare_server.py"');
      Bat.SaveToFile(AppDir + '\run_server.bat');
    except
    end;
    Bat.Free;
  end;
end;
