; =============================================================================
;  FLARE Client (Agent) -- Inno Setup installer script
;  Compile:  ISCC.exe client_setup.iss
;  Output:   Output\FLARE_Client_Setup.exe
; =============================================================================

#define AppName      "FLARE Agent"
#define AppPublisher "FLARE Security"
#define AppId        "{{B2C3D4E5-F6A7-8901-BCDE-F12345678901}"

[Setup]
AppId={#AppId}
AppName={#AppName}
AppVerName={#AppName}
AppPublisher={#AppPublisher}
AppSupportURL=https://github.com/your-org/flare
DefaultDirName={autopf}\FLARE\Client
DefaultGroupName=FLARE
DirExistsWarning=no
AllowNoIcons=yes
OutputDir=Output
OutputBaseFilename=FLARE_Client_Setup
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
UninstallDisplayIcon={app}\flare_agent.py
SetupLogging=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

; =============================================================================
;  Files
; =============================================================================

[Files]
Source: "..\client\flare_agent.py";          DestDir: "{app}"; Flags: ignoreversion
Source: "..\client\flare_service.py";        DestDir: "{app}"; Flags: ignoreversion
Source: "..\client\requirements_agent.txt";  DestDir: "{app}"; Flags: ignoreversion

Source: "..\client\proto\log_schema_pb2.py"; DestDir: "{app}\proto"; Flags: ignoreversion
Source: "..\client\proto\__init__.py";       DestDir: "{app}\proto"; Flags: ignoreversion

Source: "..\client\host\host_engine.py";     DestDir: "{app}\host"; Flags: ignoreversion
Source: "..\client\host\ioc_loader.py";      DestDir: "{app}\host"; Flags: ignoreversion
Source: "..\client\host\rules.py";           DestDir: "{app}\host"; Flags: ignoreversion
Source: "..\client\host\__init__.py";        DestDir: "{app}\host"; Flags: ignoreversion

Source: "..\client\ioc\ioc_domains.txt";           DestDir: "{app}\ioc"; Flags: ignoreversion
Source: "..\client\ioc\ioc_ips.txt";               DestDir: "{app}\ioc"; Flags: ignoreversion
Source: "..\client\ioc\ioc_process_chains.txt";    DestDir: "{app}\ioc"; Flags: ignoreversion
Source: "..\client\ioc\ioc_process_names.txt";     DestDir: "{app}\ioc"; Flags: ignoreversion

Source: "..\client\log_collector\cli.py";            DestDir: "{app}\log_collector"; Flags: ignoreversion
Source: "..\client\log_collector\flow.py";           DestDir: "{app}\log_collector"; Flags: ignoreversion
Source: "..\client\log_collector\flow_generator.py"; DestDir: "{app}\log_collector"; Flags: ignoreversion
Source: "..\client\log_collector\packet_info.py";    DestDir: "{app}\log_collector"; Flags: ignoreversion
Source: "..\client\log_collector\reader.py";         DestDir: "{app}\log_collector"; Flags: ignoreversion
Source: "..\client\log_collector\utils.py";          DestDir: "{app}\log_collector"; Flags: ignoreversion
Source: "..\client\log_collector\__init__.py";       DestDir: "{app}\log_collector"; Flags: ignoreversion
Source: "..\client\log_collector\__main__.py";       DestDir: "{app}\log_collector"; Flags: ignoreversion

Source: "..\client\network\flare_network_infer.py";          DestDir: "{app}\network"; Flags: ignoreversion
Source: "..\client\network\fl_train.py";                     DestDir: "{app}\network"; Flags: ignoreversion
Source: "..\client\network\__init__.py";                     DestDir: "{app}\network"; Flags: ignoreversion
Source: "..\client\network\models\feature_names.json";       DestDir: "{app}\network\models"; Flags: ignoreversion
Source: "..\client\network\models\network_mlp.pkl";          DestDir: "{app}\network\models"; Flags: ignoreversion
Source: "..\client\network\models\network_scaler.pkl";       DestDir: "{app}\network\models"; Flags: ignoreversion
Source: "..\client\network\models\network_mlp_weights.json"; DestDir: "{app}\network\models"; Flags: ignoreversion

[Dirs]
Name: "{app}\certs";    Permissions: everyone-full
Name: "{app}\logs";     Permissions: everyone-full
Name: "{app}\data";     Permissions: everyone-full
Name: "{app}\fl_labels"; Permissions: everyone-full

[Registry]
Root: HKLM; Subkey: "SOFTWARE\FLARE\Agent"; ValueType: string; ValueName: "InstallDir"; ValueData: "{app}"; Flags: uninsdeletekey

; =============================================================================
;  Tasks (checkboxes shown on the "Select Additional Tasks" page)
; =============================================================================

[Tasks]
Name: "desktopicon";    Description: "Create a &desktop shortcut";                       GroupDescription: "Shortcuts:"
Name: "installservice"; Description: "Install FLARE Agent as a Windows &service (auto-start on boot)"; GroupDescription: "Service:"
Name: "testmode";       Description: "Enable &test mode (FL retrains every 5 min instead of 24 h)";    GroupDescription: "Federated Learning:"

; =============================================================================
;  Run after install
; =============================================================================

[Run]
; 1. Python packages
Filename: "{code:GetPythonPath}"; Parameters: "-m pip install --no-input -q -r ""{app}\requirements_agent.txt"""; \
    StatusMsg: "Installing Python packages (this may take a few minutes)..."; \
    Flags: runhidden waituntilterminated

; 2. pywin32 post-install (Windows service + event log support)
Filename: "{code:GetPythonPath}"; \
    Parameters: "-c ""import sys,glob,subprocess; s=[p for p in glob.glob(sys.prefix+chr(47)+'Scripts'+chr(47)+'pywin32_postinstall.py') if __import__('os').path.exists(p)]; subprocess.call([sys.executable,s[0],'-install']) if s else None"""; \
    StatusMsg: "Configuring pywin32..."; Flags: runhidden waituntilterminated

; 3. Download TLS certs from server (script written to {app} by CurStepChanged)
Filename: "{code:GetPythonPath}"; Parameters: """{app}\flare_provision.py"""; \
    StatusMsg: "Downloading TLS certificates from server..."; \
    Flags: waituntilterminated

; 4. Register Windows service (optional task)
Filename: "{code:GetPythonPath}"; Parameters: """{app}\flare_service.py"" install"; WorkingDir: "{app}"; \
    StatusMsg: "Registering FLARE Agent Windows service..."; \
    Tasks: installservice; Flags: runhidden waituntilterminated

; 5. Start the service immediately after registering it
Filename: "{code:GetPythonPath}"; Parameters: """{app}\flare_service.py"" start"; WorkingDir: "{app}"; \
    StatusMsg: "Starting FLARE Agent service..."; \
    Tasks: installservice; Flags: runhidden waituntilterminated

; 6. Post-install: optionally open an interactive agent window (only if NOT installing as service)
Filename: "{cmd}"; Parameters: "/k ""{app}\run_agent.bat"""; WorkingDir: "{app}"; \
    Description: "Start FLARE Agent now (interactive window)"; \
    Flags: nowait postinstall skipifsilent unchecked

; =============================================================================
;  Uninstall
; =============================================================================

[UninstallRun]
Filename: "{code:GetPythonPath}"; Parameters: """{app}\flare_service.py"" stop";   WorkingDir: "{app}"; Flags: runhidden waituntilterminated; RunOnceId: "StopSvc"
Filename: "{code:GetPythonPath}"; Parameters: """{app}\flare_service.py"" remove"; WorkingDir: "{app}"; Flags: runhidden waituntilterminated; RunOnceId: "RemoveSvc"

[UninstallDelete]
Type: filesandordirs; Name: "{app}"

; =============================================================================
;  Pascal code
; =============================================================================

[Code]

// ---------------------------------------------------------------------------
// Already-installed check
// ---------------------------------------------------------------------------

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

  InstallDir := ExpandConstant('{autopf}') + '\FLARE\Client';
  UninstKey  := 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\' +
                '{#AppId}' + '_is1';

  HasUninstaller := RegQueryStringValue(HKLM,   UninstKey, 'UninstallString', UninstStr) or
                    RegQueryStringValue(HKLM64, UninstKey, 'UninstallString', UninstStr);

  AlreadyHere := HasUninstaller or FileExists(InstallDir + '\flare_agent.py');

  if not AlreadyHere then Exit;

  Choice := MsgBox(
    'FLARE Agent is already installed on this machine.' + #13#10 + #13#10 +
    'Setup will not continue over an existing installation.' + #13#10 + #13#10 +
    'YES  - Uninstall existing FLARE Agent now.' + #13#10 +
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


// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------
var
  PagePythonWarn:  TWizardPage;
  PageServerWarn:  TWizardPage;
  PageNpcap:       TWizardPage;
  PageAdapter:     TInputOptionWizardPage;
  PageServerURL:   TInputQueryWizardPage;

  GAdapterNames:    TStringList;
  GAdapterGUIDs:    TStringList;
  GSelectedAdapter: String;
  GServerURL:       String;
  GTestMode:        Boolean;
  GPythonExe:       String;   // full path to python.exe, found at wizard start

  LblNpcapStatus:  TLabel;   // updated when Npcap page is shown


// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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

// Find python.exe even when the elevated process PATH is stripped.
// Search order: where.exe -> HKCU registry -> HKLM registry -> %LOCALAPPDATA% paths.
function FindPythonExe: String;
var
  Output, ExePath: String;
  SubKeys: TArrayOfString;
  WherLines: TStringList;
  i, v: Integer;
begin
  Result := 'python';  // fallback: rely on PATH if everything else fails

  // 1. where.exe — check each result, skip WindowsApps stubs (Store redirects
  //    that don't execute from elevated/redirected contexts)
  RunCapture('where python', Output);
  WherLines := TStringList.Create;
  WherLines.Text := Output;
  for i := 0 to WherLines.Count - 1 do begin
    ExePath := Trim(WherLines[i]);
    // Skip Store stubs (WindowsApps) AND the pymanager shim
    // (...\AppData\Local\Python\bin\python.exe) — the shim is per-user and fails
    // to launch under the installer's elevated/admin token (exit 1, no output).
    // Falling through lets the glob below resolve the real pythoncore-* exe.
    if (ExePath <> '') and
       (Pos('windowsapps', Lowercase(ExePath)) = 0) and
       (Pos('\python\bin\', Lowercase(ExePath)) = 0) and
       FileExists(ExePath) then begin
      WherLines.Free;
      Result := ExePath;
      Exit;
    end;
  end;
  WherLines.Free;

  // 2. HKCU (user-installed Python — elevated process can still read HKCU)
  if RegGetSubkeyNames(HKCU, 'SOFTWARE\Python\PythonCore', SubKeys) then begin
    for i := GetArrayLength(SubKeys) - 1 downto 0 do begin
      if RegQueryStringValue(HKCU,
           'SOFTWARE\Python\PythonCore\' + SubKeys[i] + '\InstallPath',
           'ExecutablePath', ExePath) then begin
        if FileExists(ExePath) then begin
          Result := ExePath;
          Exit;
        end;
      end;
    end;
  end;

  // 3. HKLM
  if RegGetSubkeyNames(HKLM, 'SOFTWARE\Python\PythonCore', SubKeys) then begin
    for i := GetArrayLength(SubKeys) - 1 downto 0 do begin
      if RegQueryStringValue(HKLM,
           'SOFTWARE\Python\PythonCore\' + SubKeys[i] + '\InstallPath',
           'ExecutablePath', ExePath) then begin
        if FileExists(ExePath) then begin
          Result := ExePath;
          Exit;
        end;
      end;
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
    ' | Where-Object { $_.FullName -notlike ''*WindowsApps*''' +
    ' -and $_.FullName -notlike ''*\Python\bin\*'' }' +
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

// Called by {code:GetPythonPath} in [Run] / [UninstallRun] sections
function GetPythonPath(Param: String): String;
begin
  Result := GPythonExe;
end;

function PythonOK: Boolean;
var Output: String;
begin
  // If FindPythonExe resolved a real path, trust it — don't exec python in
  // the elevated context where the user PATH is stripped.
  if GPythonExe <> 'python' then begin
    Result := FileExists(GPythonExe);
    Exit;
  end;
  Result := RunCapture('"' + GPythonExe + '" --version', Output) = 0;
end;

function NpcapInstalled: Boolean;
begin
  Result := RegKeyExists(HKLM, 'SOFTWARE\Npcap') or
            RegKeyExists(HKLM, 'SOFTWARE\WOW6432Node\Npcap');
end;

// Test if the server URL responds (hits /api/provision/health, ignores TLS
// errors). Uses PowerShell — NOT python — because the installer runs elevated
// and the user's python may be a per-user pymanager shim that fails under the
// admin token, producing a false "unreachable" warning even when the server is up.
function TestServerReachable(URL: String): Boolean;
var
  Cmd, Output, Q: String;
begin
  Q := '''';  // single-quote char, for embedding string literals in the PS command
  Cmd := 'powershell -NoProfile -ExecutionPolicy Bypass -Command "' +
         '$ErrorActionPreference=' + Q + 'SilentlyContinue' + Q + ';' +
         '[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12;' +
         '[Net.ServicePointManager]::ServerCertificateValidationCallback={$true};' +
         'try{$r=[Net.HttpWebRequest]::Create(' + Q + URL + '/api/provision/health' + Q + ');' +
         '$r.Timeout=10000;$resp=$r.GetResponse();' +
         'if([int]$resp.StatusCode -eq 200){Write-Output ' + Q + 'OK' + Q + '};' +
         '$resp.Close()}catch{}' +
         '"';
  RunCapture(Cmd, Output);
  Result := Pos('OK', Trim(Output)) > 0;
end;

// Returns 'https://ip:port' from UDP beacon, or '' if none received in ~8 s
function BeaconDiscover: String;
var
  Cmd, Output: String;
begin
  // Use PowerShell (always present, works elevated) rather than python — the
  // installer runs elevated and the user's python may be a per-user pymanager
  // shim that fails to launch under the admin token (exit 1, no output).
  // Listens ~9 s for the server's UDP/37020 beacon: FLARE_SERVER::<ip>::<port>.
  Cmd := 'powershell -NoProfile -ExecutionPolicy Bypass -Command "' +
         '$ErrorActionPreference=''SilentlyContinue'';' +
         '$u=New-Object Net.Sockets.UdpClient(37020);' +
         '$u.Client.ReceiveTimeout=9000;' +
         '$e=New-Object Net.IPEndPoint([Net.IPAddress]::Any,0);' +
         'try{$d=$u.Receive([ref]$e);' +
         '$m=[Text.Encoding]::UTF8.GetString($d);' +
         '$p=$m -split ''::'';' +
         'if($p.Length -eq 3 -and $p[0] -eq ''FLARE_SERVER''){' +
         'Write-Output (''https://''+$p[1]+'':''+$p[2])}}' +
         'catch{};$u.Close()"';
  RunCapture(Cmd, Output);
  Output := Trim(Output);
  // Only accept a genuine URL — never leak stray output into the URL field
  if Pos('http', Output) = 1 then
    Result := Output
  else
    Result := '';
end;

// Enumerate active network adapters via PowerShell
procedure EnumAdapters;
var
  Cmd, Output, Line: String;
  Lines, Parts: TStringList;
  i: Integer;
begin
  GAdapterNames := TStringList.Create;
  GAdapterGUIDs := TStringList.Create;

  Cmd := 'powershell -NoProfile -ExecutionPolicy Bypass -Command ' +
         '"Get-NetAdapter | Where-Object { $_.Status -eq ''Up'' } | ' +
         'ForEach-Object { $_.Name + ''|'' + $_.InterfaceDescription }"';
  RunCapture(Cmd, Output);

  Lines := TStringList.Create;
  try
    Lines.Text := Output;
    for i := 0 to Lines.Count - 1 do begin
      Line := Trim(Lines[i]);
      if Line = '' then Continue;
      Parts := TStringList.Create;
      Parts.Delimiter     := '|';
      Parts.DelimitedText := Line;
      if Parts.Count >= 2 then begin
        GAdapterNames.Add(Parts[0] + '  (' + Parts[1] + ')');
        GAdapterGUIDs.Add(Parts[0]);
      end;
      Parts.Free;
    end;
  finally
    Lines.Free;
  end;

  if GAdapterNames.Count = 0 then begin
    GAdapterNames.Add('Ethernet  (fallback - no adapters detected)');
    GAdapterGUIDs.Add('Ethernet');
    GAdapterNames.Add('Wi-Fi  (fallback)');
    GAdapterGUIDs.Add('Wi-Fi');
  end;
end;

procedure WriteAgentEnv(ServerURL, AdapterName, AppDir, DataDir, TestMode: String);
var
  Lines: TStringList;
begin
  Lines := TStringList.Create;
  try
    Lines.Add('# FLARE Agent Configuration - written by installer');
    Lines.Add('FLARE_SERVER_URL='    + ServerURL);
    Lines.Add('FLARE_CA_CERT='       + DataDir + '\certs\ca.crt');
    Lines.Add('FLARE_CLIENT_CERT='   + DataDir + '\certs\client.crt');
    Lines.Add('FLARE_CLIENT_KEY='    + DataDir + '\certs\client.key');
    Lines.Add('FLARE_ADAPTER='       + AdapterName);
    Lines.Add('FLARE_FL_TEST_MODE='  + TestMode);
    // agent.env must live in the install dir — that is where flare_agent.py looks for it
    Lines.SaveToFile(AppDir + '\agent.env');
  except
  end;
  Lines.Free;
end;

procedure WriteProvisionScript(ServerURL, DataDir, AppDir: String);
var
  Script: String;
begin
  // /api/provision returns a ZIP containing ca.crt, client.crt, client.key
  // Requires ?token=<PROVISION_TOKEN>&client=<hostname>
  // Script is saved to {app} so users can re-run it manually after install.
  Script :=
    'import os, sys, socket, zipfile, io, warnings, requests' + #10 +
    'warnings.filterwarnings("ignore")' + #10 +
    'server   = "' + ServerURL + '"' + #10 +
    'cert_dir = r"' + DataDir + '\certs"' + #10 +
    'hostname = socket.gethostname()' + #10 +
    'os.makedirs(cert_dir, exist_ok=True)' + #10 +
    'try:' + #10 +
    '    url = server + "/api/provision?token=flare&client=" + hostname' + #10 +
    '    r = requests.get(url, verify=False, timeout=(10, 30))' + #10 +
    '    r.raise_for_status()' + #10 +
    '    zf = zipfile.ZipFile(io.BytesIO(r.content))' + #10 +
    '    zf.extract("ca.crt",     cert_dir)' + #10 +
    '    zf.extract("client.crt", cert_dir)' + #10 +
    '    zf.extract("client.key", cert_dir)' + #10 +
    '    open(os.path.join(cert_dir, "provision.ok"), "w").write("ok")' + #10 +
    '    print("Certificates downloaded OK ->", cert_dir)' + #10 +
    'except Exception as e:' + #10 +
    '    open(os.path.join(cert_dir, "provision.err"), "w").write(str(e))' + #10 +
    '    print("FAILED:", e)' + #10 +
    '    sys.exit(1)';
  // Write to install dir — persists after install so user can re-run if needed
  SaveStringToFile(AppDir + '\flare_provision.py', Script, False);
end;


// ---------------------------------------------------------------------------
// Wizard pages
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

// ---------------------------------------------------------------------------

// Open inbound UDP 37020 so the discovery listener (and later the agent) can
// receive the server's LAN beacon. Must run BEFORE the Server URL page does its
// auto-discovery, otherwise Windows Firewall drops the inbound broadcast and the
// URL field stays empty. Idempotent: delete-then-add avoids duplicate rules.
procedure EnsureBeaconFirewall;
var
  rc: Integer;
begin
  Exec(ExpandConstant('{cmd}'),
       '/c netsh advfirewall firewall delete rule name="FLARE-Beacon-Inbound" >nul 2>&1 & ' +
       'netsh advfirewall firewall add rule name="FLARE-Beacon-Inbound" ' +
       'dir=in action=allow protocol=UDP localport=37020 >nul 2>&1',
       '', SW_HIDE, ewWaitUntilTerminated, rc);
end;

procedure InitializeWizard;
var
  Lbl:  TLabel;
  Bevel: TBevel;
  Memo: TMemo;
  i: Integer;
begin
  // Open the beacon port first so discovery on the Server URL page can succeed.
  EnsureBeaconFirewall;

  // Locate python.exe before any wizard page that needs to run Python
  GPythonExe := FindPythonExe;

  // ── 1. Python warning ────────────────────────────────────────────────────
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
  Lbl.Caption  := 'WARNING: Python 3.10+ must be installed before you continue.';
  Lbl.WordWrap := True;
  Lbl.Font.Size  := 11;
  Lbl.Font.Style := [fsBold];
  Lbl.Font.Color := $356bff;

  Memo := TMemo.Create(PagePythonWarn);
  Memo.Parent     := PagePythonWarn.Surface;
  Memo.SetBounds(0, 52, PagePythonWarn.SurfaceWidth, 200);
  Memo.ReadOnly   := True;
  Memo.ScrollBars := ssVertical;
  Memo.Color      := $3a1f1a;
  Memo.Font.Color := $ede6e0;
  Memo.Font.Size  := 10;
  Memo.Lines.Add('HOW TO INSTALL PYTHON:');
  Memo.Lines.Add('');
  Memo.Lines.Add('  1. Go to  https://python.org/downloads');
  Memo.Lines.Add('  2. Download Python 3.10 or later (3.12 recommended).');
  Memo.Lines.Add('  3. Run the installer.');
  Memo.Lines.Add('     !! TICK "Add Python to PATH" before clicking Install Now.');
  Memo.Lines.Add('  4. Click Close once it finishes, then re-run this setup.');
  Memo.Lines.Add('');
  Memo.Lines.Add('Verify Python is on PATH:  open a new Command Prompt and run');
  Memo.Lines.Add('  python --version');

  Lbl := TLabel.Create(PagePythonWarn);
  Lbl.Parent   := PagePythonWarn.Surface;
  Lbl.SetBounds(0, 262, PagePythonWarn.SurfaceWidth, 18);
  Lbl.Caption  := 'Click Next to continue if Python is already installed.';
  Lbl.Font.Size  := 9;
  Lbl.Font.Color := $a69288;

  // ── 2. Server-must-run-first warning ─────────────────────────────────────
  PageServerWarn := CreateCustomPage(PagePythonWarn.ID,
    'Important - FLARE Server Must Be Running',
    'The server must be installed and running before you continue.');

  Bevel := TBevel.Create(PageServerWarn);
  Bevel.Parent := PageServerWarn.Surface;
  Bevel.SetBounds(0, 0, PageServerWarn.SurfaceWidth, 4);
  Bevel.Style := bsLowered;

  Lbl := TLabel.Create(PageServerWarn);
  Lbl.Parent   := PageServerWarn.Surface;
  Lbl.SetBounds(0, 14, PageServerWarn.SurfaceWidth, 28);
  Lbl.Caption  := 'WARNING: Install and start FLARE Server before continuing here.';
  Lbl.WordWrap := True;
  Lbl.Font.Size  := 10;
  Lbl.Font.Style := [fsBold];
  Lbl.Font.Color := $356bff;

  Memo := TMemo.Create(PageServerWarn);
  Memo.Parent     := PageServerWarn.Surface;
  Memo.SetBounds(0, 52, PageServerWarn.SurfaceWidth, 230);
  Memo.ReadOnly   := True;
  Memo.ScrollBars := ssVertical;
  Memo.Color      := $3a1f1a;
  Memo.Font.Color := $ede6e0;
  Memo.Font.Size  := 10;
  Memo.Lines.Add('WHY THIS MATTERS:');
  Memo.Lines.Add('');
  Memo.Lines.Add('  This installer will auto-discover the FLARE Server on your LAN');
  Memo.Lines.Add('  and download TLS certificates from it. Without a running server,');
  Memo.Lines.Add('  certificate download will fail and the agent cannot connect.');
  Memo.Lines.Add('');
  Memo.Lines.Add('CHECKLIST BEFORE CLICKING NEXT:');
  Memo.Lines.Add('');
  Memo.Lines.Add('  [ ] Run FLARE_Server_Setup.exe on the server machine.');
  Memo.Lines.Add('  [ ] Start the FLARE Server (choose option 1 or 2 in the menu).');
  Memo.Lines.Add('  [ ] Confirm port 7331 is not blocked by a firewall between');
  Memo.Lines.Add('      this machine and the server.');
  Memo.Lines.Add('');
  Memo.Lines.Add('  TIP: Auto-discovery listens on UDP port 37020. If that is');
  Memo.Lines.Add('  blocked you can type the server URL manually on the next step.');

  // ── 3. Npcap check ───────────────────────────────────────────────────────
  PageNpcap := CreateCustomPage(PageServerWarn.ID,
    'Packet Capture Driver - Npcap',
    'FLARE requires Npcap to capture network traffic.');

  Bevel := TBevel.Create(PageNpcap);
  Bevel.Parent := PageNpcap.Surface;
  Bevel.SetBounds(0, 0, PageNpcap.SurfaceWidth, 4);
  Bevel.Style := bsLowered;

  LblNpcapStatus := TLabel.Create(PageNpcap);
  LblNpcapStatus.Parent   := PageNpcap.Surface;
  LblNpcapStatus.SetBounds(0, 14, PageNpcap.SurfaceWidth, 22);
  LblNpcapStatus.Caption  := 'Checking for Npcap...';
  LblNpcapStatus.Font.Size  := 11;
  LblNpcapStatus.Font.Style := [fsBold];

  Memo := TMemo.Create(PageNpcap);
  Memo.Parent     := PageNpcap.Surface;
  Memo.SetBounds(0, 46, PageNpcap.SurfaceWidth, 200);
  Memo.ReadOnly   := True;
  Memo.ScrollBars := ssVertical;
  Memo.Color      := $3a1f1a;
  Memo.Font.Color := $ede6e0;
  Memo.Font.Size  := 10;
  Memo.Lines.Add('Npcap is the packet capture driver used by FLARE to inspect');
  Memo.Lines.Add('network traffic. Without it, the network monitoring track will');
  Memo.Lines.Add('not function (host monitoring still works).');
  Memo.Lines.Add('');
  Memo.Lines.Add('HOW TO INSTALL NPCAP (free):');
  Memo.Lines.Add('');
  Memo.Lines.Add('  1. Go to  https://npcap.com/#download');
  Memo.Lines.Add('  2. Download the latest Npcap installer.');
  Memo.Lines.Add('  3. Run it (tick "WinPcap compatibility mode").');
  Memo.Lines.Add('  4. Reboot if prompted, then re-run this installer.');
  Memo.Lines.Add('');
  Memo.Lines.Add('You may click Next to skip and install Npcap later,');
  Memo.Lines.Add('but network detection will be disabled until it is installed.');

  Lbl := TLabel.Create(PageNpcap);
  Lbl.Parent   := PageNpcap.Surface;
  Lbl.SetBounds(0, 256, PageNpcap.SurfaceWidth, 18);
  Lbl.Caption  := 'Click Next to continue anyway, or install Npcap and re-run setup.';
  Lbl.Font.Size  := 9;
  Lbl.Font.Color := $a69288;

  // ── 4. Adapter selection ─────────────────────────────────────────────────
  EnumAdapters;
  PageAdapter := CreateInputOptionPage(PageNpcap.ID,
    'Network Adapter',
    'Select the adapter FLARE should monitor for traffic.',
    'Active adapters on this machine:', False, False);

  for i := 0 to GAdapterNames.Count - 1 do
    PageAdapter.Add(GAdapterNames[i]);
  if GAdapterNames.Count > 0 then
    PageAdapter.SelectedValueIndex := 0;

  // ── 5. Server URL ─────────────────────────────────────────────────────────
  PageServerURL := CreateInputQueryPage(PageAdapter.ID,
    'FLARE Server Address',
    'Enter the URL of your FLARE Server.',
    'The installer will try to auto-discover the server on your LAN ' +
    '(takes ~8 seconds). You can also type the address manually.');

  PageServerURL.Add('Server URL  (e.g. https://192.168.1.10:7331):', False);
  PageServerURL.Values[0] := '';

  // Paint the whole wizard dark now that every custom page exists.
  ApplyDarkTheme;
end;


// ---------------------------------------------------------------------------
// Page events
// ---------------------------------------------------------------------------

procedure CurPageChanged(CurPageID: Integer);
var
  Discovered: String;
begin
  // Re-assert the dark theme on every page (some controls are created lazily).
  ApplyDarkTheme;

  // Update Npcap status label when that page is shown
  if CurPageID = PageNpcap.ID then begin
    if NpcapInstalled then begin
      LblNpcapStatus.Caption  := 'Npcap is installed.  You are good to go.';
      LblNpcapStatus.Font.Color := $1ac452;
    end else begin
      LblNpcapStatus.Caption  := 'Npcap NOT detected on this machine.';
      LblNpcapStatus.Font.Color := $356bff;
    end;
  end;

  // Auto-discover server when URL page is shown
  if CurPageID = PageServerURL.ID then begin
    if PageServerURL.Values[0] = '' then begin
      WizardForm.NextButton.Enabled := False;
      WizardForm.NextButton.Caption := 'Discovering...';
      Discovered := BeaconDiscover;
      WizardForm.NextButton.Caption := 'Next >';
      WizardForm.NextButton.Enabled := True;
      if Discovered <> '' then
        PageServerURL.Values[0] := Discovered;
    end;
  end;
end;

function NextButtonClick(CurPageID: Integer): Boolean;
var
  URL: String;
begin
  Result := True;

  // Hard block if Python missing
  if CurPageID = PagePythonWarn.ID then begin
    if not PythonOK then begin
      MsgBox(
        'Python was not found on this machine.' + #13#10 + #13#10 +
        'Install Python 3.10+ from  https://python.org/downloads' + #13#10 +
        'Tick "Add Python to PATH" during install, then re-run this setup.',
        mbCriticalError, MB_OK);
      Result := False;
      Exit;
    end;
  end;

  // Capture adapter choice
  if CurPageID = PageAdapter.ID then begin
    if GAdapterGUIDs.Count > PageAdapter.SelectedValueIndex then
      GSelectedAdapter := GAdapterGUIDs[PageAdapter.SelectedValueIndex]
    else
      GSelectedAdapter := 'Ethernet';
  end;

  // Validate URL format, then test reachability
  if CurPageID = PageServerURL.ID then begin
    URL := Trim(PageServerURL.Values[0]);
    if (URL = '') or
       ((Pos('https://', URL) = 0) and (Pos('http://', URL) = 0)) then begin
      MsgBox(
        'Please enter a valid server URL.' + #13#10 +
        'Example:  https://192.168.1.10:7331',
        mbError, MB_OK);
      Result := False;
      Exit;
    end;

    // Test reachability (non-blocking warning if it fails)
    WizardForm.NextButton.Enabled := False;
    WizardForm.NextButton.Caption := 'Testing...';
    if not TestServerReachable(URL) then begin
      WizardForm.NextButton.Caption := 'Next >';
      WizardForm.NextButton.Enabled := True;
      if MsgBox(
        'Could not reach the FLARE Server at:' + #13#10 +
        '  ' + URL + #13#10 + #13#10 +
        'Possible causes:' + #13#10 +
        '  - Server is not running' + #13#10 +
        '  - Firewall is blocking port' + #13#10 +
        '  - Wrong IP or port' + #13#10 + #13#10 +
        'Continue anyway? (cert download will likely fail)',
        mbConfirmation, MB_YESNO) = IDNO then begin
        Result := False;
        Exit;
      end;
    end else begin
      WizardForm.NextButton.Caption := 'Next >';
      WizardForm.NextButton.Enabled := True;
    end;

    GServerURL := URL;
  end;
end;


// ---------------------------------------------------------------------------
// Post-install: write config files, verify certs
// ---------------------------------------------------------------------------

procedure CurStepChanged(CurStep: TSetupStep);
var
  TestModeStr: String;
  AppDir: String;
  Bat: TStringList;
begin
  if CurStep = ssPostInstall then begin
    if GSelectedAdapter = '' then GSelectedAdapter := 'Ethernet';
    if GServerURL       = '' then GServerURL       := 'https://127.0.0.1:7331';

    if WizardIsTaskSelected('testmode') then TestModeStr := '1'
                                       else TestModeStr := '0';
    GTestMode := TestModeStr = '1';
    AppDir := ExpandConstant('{app}');

    WriteAgentEnv(GServerURL, GSelectedAdapter, AppDir, AppDir, TestModeStr);
    WriteProvisionScript(GServerURL, AppDir, AppDir);

    // Write launcher batch so the postinstall "Run now" entry has no quoting issues
    Bat := TStringList.Create;
    try
      Bat.Add('@echo off');
      Bat.Add('"' + GPythonExe + '" "' + AppDir + '\flare_agent.py"');
      Bat.SaveToFile(AppDir + '\run_agent.bat');
    except
    end;
    Bat.Free;
  end;

  // No cert verification needed here: the agent self-provisions its certs from
  // the server on first run (see _ensure_certs in flare_agent.py), so a failed
  // installer-time provision is no longer fatal.
end;
