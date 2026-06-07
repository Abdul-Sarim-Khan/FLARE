# -*- coding: utf-8 -*-
"""
FLARE v0.6 - Rule Definitions
────────────────────────────
Each rule is a function:
    check_*(event: dict, ioc: IOCLoader, state: RuleState) -> Optional[RuleResult]

event dict keys (always present):
    channel     str   e.g. "Security"
    event_id    int   e.g. 4769
    timestamp   str   ISO-8601
    computer    str   machine name
    + channel-specific fields extracted from the event XML

RuleResult carries everything needed to build an AlertEvent proto.

Confidence scale:
    1.00  deterministic exact match — zero ambiguity
    0.95  near-certain  — IOC match or known-bad signature
    0.90  high          — strong heuristic, very rare legitimate use
    0.85  medium-high   — threshold-based, context-dependent
    0.75  medium        — pattern-based, some legitimate overlap

Severity mapping (applied in host_engine.py):
    conf >= 0.95  ->  CRITICAL
    conf >= 0.85  ->  HIGH
    conf >= 0.75  ->  MEDIUM
    else          ->  LOW
"""

import collections
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Optional

from ioc_loader import IOCLoader


# ─────────────────────────────────────────────────────────────────────────────
# RuleResult — what every rule returns on a match
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class RuleResult:
    rule_id:      str
    attack_type:  str
    confidence:   float
    mitre_id:     str
    mitre_tactic: str
    suggestion:   str
    risk_note:    str
    evidence:     dict = field(default_factory=dict)


# ─────────────────────────────────────────────────────────────────────────────
# RuleState — holds sliding-window counters for threshold rules
# Thread-safe.
# ─────────────────────────────────────────────────────────────────────────────

class RuleState:
    """
    Maintains per-IP / per-key sliding windows for threshold-based rules.
    Internally uses a deque of (timestamp, value) tuples per key.
    """

    WINDOW_SECS = 60  # all thresholds measured over a 60-second window

    def __init__(self):
        self._lock     = threading.Lock()
        # key -> deque of (timestamp, value) tuples
        self._counters: dict[str, collections.deque] = collections.defaultdict(
            lambda: collections.deque()
        )
        # key -> monotonic time of the last alert fired (for dedup cooldown)
        self._last_alert: dict[str, float] = {}

    def record(self, key: str, value: str = "") -> tuple[int, int]:
        """
        Record one event for (key, value).
        Returns (total_count, distinct_value_count) within the window.
        """
        now    = time.monotonic()
        cutoff = now - self.WINDOW_SECS

        with self._lock:
            dq = self._counters[key]
            dq.append((now, value))
            # Evict entries that have aged out of the window
            while dq and dq[0][0] < cutoff:
                dq.popleft()
            total    = len(dq)
            distinct = len({v for _, v in dq if v})

            # Fix 10: evict keys whose window is now empty to prevent memory
            # accumulating for IPs/keys that are no longer generating events.
            if not dq:
                del self._counters[key]

            # Evict stale alert-suppression entries (older than 2x window) so
            # the _last_alert dict doesn't grow unboundedly on long-running agents.
            stale_cutoff = now - 2 * self.WINDOW_SECS
            if self._last_alert:
                self._last_alert = {
                    k: v for k, v in self._last_alert.items()
                    if v >= stale_cutoff
                }

        return total, distinct

    def check_and_record_alert(self, key: str) -> bool:
        """
        Return True and record the alert time if no alert has fired for *key*
        within the last WINDOW_SECS seconds (i.e. this is the first alert for
        this burst).  Return False if the alert should be suppressed to avoid
        duplicate firing on every event after the threshold is crossed.
        """
        now = time.monotonic()
        with self._lock:
            last = self._last_alert.get(key, 0.0)
            if now - last >= self.WINDOW_SECS:
                self._last_alert[key] = now
                return True
            return False

    def clear(self, key: str):
        with self._lock:
            self._counters.pop(key, None)
            self._last_alert.pop(key, None)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

_PS_DOWNLOAD_PATTERNS = re.compile(
    r"(IEX|Invoke-Expression|DownloadString|DownloadFile|WebClient|"
    r"Net\.WebClient|Invoke-WebRequest|Start-BitsTransfer|"
    r"New-Object.*Net\.WebClient)",
    re.IGNORECASE,
)

_PS_ENCODED_PATTERNS = re.compile(
    r"(FromBase64String|ToBase64String|-EncodedCommand|-enc\s|"
    r"\[Convert\]::FromBase64)",
    re.IGNORECASE,
)

_PS_REFLECTION_PATTERNS = re.compile(
    r"(Reflection\.Assembly|Load\(|LoadWithPartialName|"
    r"GetMethod|Invoke.*null|DllImport)",
    re.IGNORECASE,
)

_SUSPICIOUS_PATH_PATTERNS = re.compile(
    r"(\\Temp\\|\\tmp\\|%temp%|%tmp%|\\AppData\\|"
    r"\\Users\\[^\\]+\\Desktop\\|\\Users\\[^\\]+\\Downloads\\|"
    r"\\ProgramData\\[^\\]+\.exe|\\Public\\)",
    re.IGNORECASE,
)

_SHADOW_DELETE_PATTERN = re.compile(
    r"(delete\s+shadows|resize\s+shadowstorage|shadowcopy\s+delete)",
    re.IGNORECASE,
)

_SCHEDULED_TASK_SUSPICIOUS = re.compile(
    r"(powershell|cmd\.exe|wscript|cscript|mshta|regsvr32|rundll32|"
    r"\\Temp\\|\\AppData\\|\\ProgramData\\|encoded|hidden|bypass)",
    re.IGNORECASE,
)

PRIVILEGED_GROUPS = {
    "administrators", "domain admins", "enterprise admins",
    "schema admins", "group policy creator owners",
    "account operators", "backup operators", "server operators",
    "print operators", "remote desktop users", "distributed com users",
    "network configuration operators",
}


def _snip(text: str, max_len: int = 300) -> str:
    """Truncate long strings for evidence fields."""
    return text[:max_len] + "…" if len(text) > max_len else text


# ─────────────────────────────────────────────────────────────────────────────
# ── CREDENTIAL ACCESS ────────────────────────────────────────────────────────
# ─────────────────────────────────────────────────────────────────────────────

def check_kerberoasting(event: dict, ioc: IOCLoader, state: RuleState) -> Optional[RuleResult]:
    """
    Event 4769 — Kerberos service ticket requested with RC4 encryption.
    RC4 (0x17) tickets can be cracked offline. No legitimate modern Kerberos
    client requests RC4 for service tickets.
    """
    if event["event_id"] != 4769:
        return None
    enc = event.get("TicketEncryptionType", "").strip()
    if enc not in ("0x17", "23"):       # 0x17 = 23 decimal = RC4-HMAC
        return None
    svc = event.get("ServiceName", "")
    if svc.endswith("$"):               # machine account ticket — ignore
        return None

    return RuleResult(
        rule_id      = "kerberoasting_rc4",
        attack_type  = "Kerberoasting via RC4 Downgrade",
        confidence   = 1.0,
        mitre_id     = "T1558.003",
        mitre_tactic = "Credential Access",
        suggestion   = (
            f"Audit SPNs on service account '{event.get('ServiceName', '?')}'. "
            "Force AES-only Kerberos on service accounts (msDS-SupportedEncryptionTypes). "
            f"Investigate source host {event.get('ClientAddress', '?')} for cracking tools."
        ),
        risk_note    = (
            "RC4 Kerberos service tickets can be cracked offline in minutes using Hashcat. "
            "A successful crack yields service account credentials with no further DC interaction."
        ),
        evidence = {
            "event_id":              4769,
            "ServiceName":           svc,
            "TargetUserName":        event.get("TargetUserName", ""),
            "ClientAddress":         event.get("ClientAddress", ""),
            "TicketEncryptionType":  enc,
        },
    )


def check_asrep_roasting(event: dict, ioc: IOCLoader, state: RuleState) -> Optional[RuleResult]:
    """
    Event 4768 — Kerberos pre-authentication not required (AS-REP Roasting).
    Status 0x0 with pre-auth disabled, or explicit pre-auth not required flag.
    """
    if event["event_id"] != 4768:
        return None
    # Pre-auth disabled is indicated by the PreAuthType field being 0
    pre_auth = event.get("PreAuthType", "1").strip()
    if pre_auth != "0":
        return None

    return RuleResult(
        rule_id      = "asrep_roasting",
        attack_type  = "AS-REP Roasting (Pre-Auth Disabled)",
        confidence   = 0.95,
        mitre_id     = "T1558.004",
        mitre_tactic = "Credential Access",
        suggestion   = (
            f"Enable Kerberos pre-authentication on account '{event.get('TargetUserName', '?')}'. "
            "Audit all accounts with 'Do not require Kerberos preauthentication' set. "
            f"Check source {event.get('IpAddress', '?')} for offline cracking activity."
        ),
        risk_note    = (
            "Accounts with pre-auth disabled leak an encrypted blob the attacker can crack "
            "offline without authenticating at all — no credentials needed to start the attack."
        ),
        evidence = {
            "event_id":       4768,
            "TargetUserName": event.get("TargetUserName", ""),
            "IpAddress":      event.get("IpAddress", ""),
            "PreAuthType":    pre_auth,
        },
    )


def _resolve_src(event: dict) -> str:
    """
    Return the best available source identifier from a logon event.
    Windows writes '-' for IpAddress on local interactive/network-API logons
    (e.g. LogonUserW called on the same machine). Fall back to WorkstationName,
    then the Computer field, so we never surface a bare '-' in alerts.
    """
    ip = event.get("IpAddress", "").strip()
    if ip and ip != "-":
        return ip
    ws = event.get("WorkstationName", "").strip()
    if ws and ws != "-":
        return ws
    comp = event.get("computer", "").strip()
    if comp and comp != "-":
        return comp
    return "local"


def check_brute_force(event: dict, ioc: IOCLoader, state: RuleState) -> Optional[RuleResult]:
    """
    Event 4625 — Failed logon. Threshold: >10 failures from same IP in 60s.
    """
    if event["event_id"] != 4625:
        return None
    src_ip   = _resolve_src(event)
    username = event.get("TargetUserName", "")

    total, distinct = state.record(f"brute:{src_ip}", username)

    if total >= 10:
        # Fix 5: suppress duplicate alerts — only fire once per WINDOW_SECS
        # burst to avoid N-threshold alerts for a single attack wave.
        if not state.check_and_record_alert(f"brute:{src_ip}"):
            return None
        return RuleResult(
            rule_id      = "brute_force_logon",
            attack_type  = "Brute Force Logon Attempt",
            confidence   = 0.85,
            mitre_id     = "T1110.001",
            mitre_tactic = "Credential Access",
            suggestion   = (
                f"Block or isolate {src_ip}. "
                "Review account lockout policy. "
                "Check for active logon sessions from this source."
            ),
            risk_note    = (
                f"{total} failed logons from {src_ip} within 60 seconds. "
                "Automated credential stuffing or brute force in progress."
            ),
            evidence = {
                "event_id":        4625,
                "src_ip":          src_ip,
                "failure_count":   total,
                "last_username":   username,
                "SubStatus":       event.get("SubStatus", ""),
            },
        )
    return None


def check_password_spray(event: dict, ioc: IOCLoader, state: RuleState) -> Optional[RuleResult]:
    """
    Event 4625 — Password spray: same IP failing against 5+ distinct usernames in 60s.
    Distinct from brute force (one target, many passwords) — spray hits many targets once.
    """
    if event["event_id"] != 4625:
        return None
    src_ip   = _resolve_src(event)
    username = event.get("TargetUserName", "")

    total, distinct = state.record(f"spray:{src_ip}", username)

    if distinct >= 5 and total >= 5:
        # Fix 5: suppress duplicate alerts — only fire once per WINDOW_SECS
        # burst to avoid N-threshold alerts for a single spray wave.
        if not state.check_and_record_alert(f"spray:{src_ip}"):
            return None
        return RuleResult(
            rule_id      = "password_spray",
            attack_type  = "Password Spray Attack",
            confidence   = 0.90,
            mitre_id     = "T1110.003",
            mitre_tactic = "Credential Access",
            suggestion   = (
                f"Block {src_ip} immediately. "
                "Audit accounts targeted — check for any successful logons after the spray. "
                "Enable MFA on all accounts if not already enforced."
            ),
            risk_note    = (
                f"{src_ip} attempted {distinct} distinct usernames in 60 seconds. "
                "Password spray evades lockout policies by attempting one password per account. "
                "A single hit yields valid credentials."
            ),
            evidence = {
                "event_id":       4625,
                "src_ip":         src_ip,
                "distinct_users": distinct,
                "total_attempts": total,
                "last_username":  username,
            },
        )
    return None


# ─────────────────────────────────────────────────────────────────────────────
# ── EXECUTION ────────────────────────────────────────────────────────────────
# ─────────────────────────────────────────────────────────────────────────────

def check_ps_download_cradle(event: dict, ioc: IOCLoader, state: RuleState) -> Optional[RuleResult]:
    """
    Event 4104 — PowerShell script block logging.
    Detects download-and-execute patterns (IEX, WebClient, DownloadString, etc.)
    Legitimate production scripts do not download and execute code at runtime.
    """
    if event["event_id"] != 4104:
        return None
    text = event.get("ScriptBlockText", "")
    m    = _PS_DOWNLOAD_PATTERNS.search(text)
    if not m:
        return None

    return RuleResult(
        rule_id      = "ps_download_cradle",
        attack_type  = "PowerShell Download Cradle",
        confidence   = 0.95,
        mitre_id     = "T1059.001",
        mitre_tactic = "Execution",
        suggestion   = (
            "Capture the full script block from Event 4104 in the PowerShell log. "
            "Identify what URL/payload was downloaded. "
            "Check network connections made by the PowerShell process around this timestamp."
        ),
        risk_note    = (
            f"PowerShell is downloading and executing code at runtime using '{m.group(1)}'. "
            "This pattern is the primary delivery mechanism for Cobalt Strike, Empire, and "
            "commodity RATs. The payload never touches disk before execution."
        ),
        evidence = {
            "event_id":      4104,
            "trigger":       m.group(1),
            "script_snip":   _snip(text),
            "script_path":   event.get("Path", "<no path>"),
        },
    )


def check_ps_encoded(event: dict, ioc: IOCLoader, state: RuleState) -> Optional[RuleResult]:
    """
    Event 4104 — Base64 encoded PowerShell execution or reflection loading.
    Legitimate scripts don't need runtime base64 decoding for execution.
    """
    if event["event_id"] != 4104:
        return None
    text = event.get("ScriptBlockText", "")
    m    = _PS_ENCODED_PATTERNS.search(text)
    if not m:
        return None

    return RuleResult(
        rule_id      = "ps_encoded_command",
        attack_type  = "PowerShell Encoded / Obfuscated Execution",
        confidence   = 0.90,
        mitre_id     = "T1027",
        mitre_tactic = "Defense Evasion",
        suggestion   = (
            "Decode the base64 payload and analyse the decoded content. "
            "Check if this script was launched with -EncodedCommand flag (Event 4688 CommandLine). "
            "Correlate with parent process."
        ),
        risk_note    = (
            "Base64 encoding is used to bypass command-line logging and AV signature scanning. "
            "This is a standard obfuscation technique for all major post-exploitation frameworks."
        ),
        evidence = {
            "event_id":    4104,
            "trigger":     m.group(1),
            "script_snip": _snip(text),
            "script_path": event.get("Path", "<no path>"),
        },
    )


def check_ps_reflection(event: dict, ioc: IOCLoader, state: RuleState) -> Optional[RuleResult]:
    """
    Event 4104 — .NET reflection assembly loading in PowerShell.
    Used to load Mimikatz and other offensive tools entirely in memory.
    """
    if event["event_id"] != 4104:
        return None
    text = event.get("ScriptBlockText", "")
    m    = _PS_REFLECTION_PATTERNS.search(text)
    if not m:
        return None

    return RuleResult(
        rule_id      = "ps_reflection_load",
        attack_type  = "PowerShell Reflection Assembly Load",
        confidence   = 0.90,
        mitre_id     = "T1620",
        mitre_tactic = "Defense Evasion",
        suggestion   = (
            "Capture the full script block. The loaded assembly never touches disk — "
            "take a memory dump of the PowerShell process if still running. "
            "Check for LSASS access following this event."
        ),
        risk_note    = (
            "Reflection-based .NET loading is the primary technique for running Mimikatz, "
            "SharpHound, and other offensive tools entirely in memory, bypassing AV."
        ),
        evidence = {
            "event_id":    4104,
            "trigger":     m.group(1),
            "script_snip": _snip(text),
        },
    )


# ─────────────────────────────────────────────────────────────────────────────
# ── PERSISTENCE ──────────────────────────────────────────────────────────────
# ─────────────────────────────────────────────────────────────────────────────

def check_psexec_service(event: dict, ioc: IOCLoader, state: RuleState) -> Optional[RuleResult]:
    """
    Event 7045 — New service installed named PSEXESVC.
    PsExec creates this service on the target machine during remote execution.
    """
    if event["event_id"] != 7045:
        return None
    if event.get("ServiceName", "").upper() != "PSEXESVC":
        return None

    return RuleResult(
        rule_id      = "psexec_lateral_movement",
        attack_type  = "PsExec Remote Execution (Lateral Movement)",
        confidence   = 1.0,
        mitre_id     = "T1569.002",
        mitre_tactic = "Lateral Movement",
        suggestion   = (
            "Identify the source machine that deployed PsExec (check Event 4648 / 4624 logon "
            "type 3 around the same timestamp). Determine what command was executed remotely. "
            "Check for follow-on credential access activity."
        ),
        risk_note    = (
            "PsExec is the most common lateral movement tool in enterprise intrusions. "
            "PSEXESVC on this machine means a remote attacker executed a command here "
            "using stolen or compromised credentials."
        ),
        evidence = {
            "event_id":    7045,
            "ServiceName": event.get("ServiceName", ""),
            "ImagePath":   event.get("ImagePath", ""),
            "AccountName": event.get("AccountName", ""),
        },
    )


def check_new_service_suspicious_path(event: dict, ioc: IOCLoader, state: RuleState) -> Optional[RuleResult]:
    """
    Event 7045 — New service installed with executable in a suspicious path.
    Legitimate services install to Program Files or Windows directories.
    """
    if event["event_id"] != 7045:
        return None
    svc_name  = event.get("ServiceName", "")
    image     = event.get("ImagePath", "")

    if svc_name.upper() == "PSEXESVC":   # handled by check_psexec_service
        return None
    if not _SUSPICIOUS_PATH_PATTERNS.search(image):
        return None

    return RuleResult(
        rule_id      = "new_service_suspicious_path",
        attack_type  = "Malicious Service Installation",
        confidence   = 0.90,
        mitre_id     = "T1543.003",
        mitre_tactic = "Persistence",
        suggestion   = (
            f"Inspect the binary at '{image}'. "
            "Check when the file was written to disk vs when the service was created. "
            "Verify the digital signature of the executable."
        ),
        risk_note    = (
            "Malware commonly installs itself as a Windows service for persistence. "
            "Legitimate software installs services in Program Files or Windows directories, "
            "not in user-writable temp or AppData locations."
        ),
        evidence = {
            "event_id":    7045,
            "ServiceName": svc_name,
            "ImagePath":   image,
            "AccountName": event.get("AccountName", ""),
        },
    )


def check_wmi_persistence(event: dict, ioc: IOCLoader, state: RuleState) -> Optional[RuleResult]:
    """
    Event 5861 — WMI event subscription created.
    WMI subscriptions survive reboots and run without any visible process.
    Virtually no legitimate software uses WMI subscriptions for persistence.
    """
    if event["event_id"] != 5861:
        return None

    return RuleResult(
        rule_id      = "wmi_persistence",
        attack_type  = "WMI Event Subscription (Persistence)",
        confidence   = 0.95,
        mitre_id     = "T1546.003",
        mitre_tactic = "Persistence",
        suggestion   = (
            "List all WMI subscriptions: Get-WMIObject -Namespace root\\subscription "
            "-Class __EventFilter | Select Name,Query. "
            "Remove any unknown subscriptions. "
            "Check what process created the subscription (correlate with Event 4688)."
        ),
        risk_note    = (
            "WMI subscriptions are a fileless persistence mechanism that executes on system "
            "events (startup, logon, timer). They survive reboots and are invisible to most "
            "endpoint tools that only scan the filesystem."
        ),
        evidence = {
            "event_id":  5861,
            "Namespace": event.get("Namespace", ""),
            "Query":     _snip(event.get("Query", ""), 200),
            "Name":      event.get("Name", ""),
            "Consumer":  event.get("Consumer", ""),
        },
    )


def check_scheduled_task_suspicious(event: dict, ioc: IOCLoader, state: RuleState) -> Optional[RuleResult]:
    """
    Event 4698 — Scheduled task created with suspicious action.
    Flags tasks that run PS, cmd, script hosts, or point to temp/appdata.
    """
    if event["event_id"] != 4698:
        return None
    task_content = event.get("TaskContentXml", event.get("TaskName", ""))
    if not _SCHEDULED_TASK_SUSPICIOUS.search(task_content):
        return None

    return RuleResult(
        rule_id      = "scheduled_task_suspicious",
        attack_type  = "Suspicious Scheduled Task Created",
        confidence   = 0.85,
        mitre_id     = "T1053.005",
        mitre_tactic = "Persistence",
        suggestion   = (
            f"Review task '{event.get('TaskName', '?')}' in Task Scheduler. "
            "Verify the action executable and its digital signature. "
            "Check who created the task (SubjectUserName field)."
        ),
        risk_note    = (
            "Attackers create scheduled tasks to maintain persistence across reboots "
            "and to execute payloads at specific intervals or on system events."
        ),
        evidence = {
            "event_id":       4698,
            "TaskName":       event.get("TaskName", ""),
            "SubjectUser":    event.get("SubjectUserName", ""),
            "task_snip":      _snip(task_content),
        },
    )


# ─────────────────────────────────────────────────────────────────────────────
# ── PRIVILEGE ESCALATION ─────────────────────────────────────────────────────
# ─────────────────────────────────────────────────────────────────────────────

def check_privileged_group_add(event: dict, ioc: IOCLoader, state: RuleState) -> Optional[RuleResult]:
    """
    Events 4728/4732/4756 — User added to a privileged security group.
    Always worth alerting — legitimate changes should be documented.
    """
    if event["event_id"] not in (4728, 4732, 4756):
        return None
    group = event.get("GroupName", "").lower()
    if not any(pg in group for pg in PRIVILEGED_GROUPS):
        return None

    return RuleResult(
        rule_id      = "privileged_group_modification",
        attack_type  = "User Added to Privileged Group",
        confidence   = 0.85,
        mitre_id     = "T1098",
        mitre_tactic = "Privilege Escalation",
        suggestion   = (
            f"Verify that adding '{event.get('MemberName', '?')}' to "
            f"'{event.get('GroupName', '?')}' was authorised. "
            "Check the account that made the change (SubjectUserName). "
            "If unauthorised, remove immediately and investigate the actor account."
        ),
        risk_note    = (
            "Adding an account to a privileged group grants permanent elevated access. "
            "This is a common post-exploitation step after initial credential compromise."
        ),
        evidence = {
            "event_id":       event["event_id"],
            "MemberName":     event.get("MemberName", ""),
            "GroupName":      event.get("GroupName", ""),
            "SubjectUser":    event.get("SubjectUserName", ""),
            "SubjectDomain":  event.get("SubjectDomainName", ""),
        },
    )


# ─────────────────────────────────────────────────────────────────────────────
# ── DEFENSE EVASION ──────────────────────────────────────────────────────────
# ─────────────────────────────────────────────────────────────────────────────

def check_audit_policy_changed(event: dict, ioc: IOCLoader, state: RuleState) -> Optional[RuleResult]:
    """
    Event 4719 — System audit policy modified.
    Attackers disable auditing to blind SIEM/EDR before moving laterally.
    """
    if event["event_id"] != 4719:
        return None

    return RuleResult(
        rule_id      = "audit_policy_changed",
        attack_type  = "Audit Policy Modified",
        confidence   = 0.95,
        mitre_id     = "T1562.002",
        mitre_tactic = "Defense Evasion",
        suggestion   = (
            "Verify this change was planned and authorised. "
            "If unexpected, restore audit policy immediately via Group Policy. "
            "Investigate the account that made the change for prior compromise indicators."
        ),
        risk_note    = (
            "Disabling audit policies is a standard pre-lateral-movement technique. "
            "The attacker is attempting to go dark before the next stage of the attack."
        ),
        evidence = {
            "event_id":           4719,
            "SubcategoryId":      event.get("SubcategoryId", ""),
            "AuditPolicyChanges": event.get("AuditPolicyChanges", ""),
            "SubjectUserName":    event.get("SubjectUserName", ""),
        },
    )


def check_defender_disabled(event: dict, ioc: IOCLoader, state: RuleState) -> Optional[RuleResult]:
    """
    Windows Defender events 5001/5010/5012 — real-time protection disabled.
    """
    if event["event_id"] not in (5001, 5010, 5012):
        return None

    label = {
        5001: "Real-Time Protection Disabled",
        5010: "Scanning for Malware Disabled",
        5012: "Behaviour Monitoring Disabled",
    }.get(event["event_id"], "Defender Component Disabled")

    return RuleResult(
        rule_id      = "defender_disabled",
        attack_type  = f"Windows Defender {label}",
        confidence   = 1.0,
        mitre_id     = "T1562.001",
        mitre_tactic = "Defense Evasion",
        suggestion   = (
            "Re-enable Windows Defender immediately. "
            "Identify what process/user disabled it (check Event 4688 around same timestamp). "
            "Assume the machine is compromised and begin IR procedures."
        ),
        risk_note    = (
            "Disabling AV is almost always the step immediately before malware deployment. "
            "The window between AV disable and payload execution is typically seconds."
        ),
        evidence = {
            "event_id":    event["event_id"],
            "description": label,
            "computer":    event.get("computer", ""),
        },
    )


def check_shadow_copy_deletion(event: dict, ioc: IOCLoader, state: RuleState) -> Optional[RuleResult]:
    """
    Event 4688 — vssadmin or wbadmin launched with shadow copy deletion arguments.
    Primary indicator of ransomware preparing to encrypt.
    """
    if event["event_id"] != 4688:
        return None
    process = event.get("NewProcessName", "").lower()
    cmdline = event.get("CommandLine", "")

    if not any(x in process for x in ("vssadmin", "wbadmin", "bcdedit", "wmic")):
        return None
    if not _SHADOW_DELETE_PATTERN.search(cmdline):
        return None

    return RuleResult(
        rule_id      = "shadow_copy_deletion",
        attack_type  = "Volume Shadow Copy Deletion (Pre-Ransomware)",
        confidence   = 1.0,
        mitre_id     = "T1490",
        mitre_tactic = "Impact",
        suggestion   = (
            "ISOLATE THIS MACHINE IMMEDIATELY from the network. "
            "Shadow copies are being deleted — ransomware encryption may be imminent or in progress. "
            "Do not reboot. Capture memory if possible before shutdown."
        ),
        risk_note    = (
            "Deleting volume shadow copies is the near-universal first step of ransomware. "
            "This removes Windows' built-in backup mechanism, ensuring victims cannot recover "
            "files without paying the ransom or restoring from external backups."
        ),
        evidence = {
            "event_id":   4688,
            "Process":    event.get("NewProcessName", ""),
            "CommandLine": _snip(cmdline),
            "ParentProcess": event.get("ParentProcessName", ""),
        },
    )


# ─────────────────────────────────────────────────────────────────────────────
# ── IOC MATCHING ─────────────────────────────────────────────────────────────
# ─────────────────────────────────────────────────────────────────────────────

def check_ioc_domain(event: dict, ioc: IOCLoader, state: RuleState) -> Optional[RuleResult]:
    """
    DNS Client Event 3008 — DNS query matches IOC domain list.
    """
    if event["event_id"] != 3008:
        return None
    query   = event.get("QueryName", "")
    matched = ioc.match_domain(query)
    if not matched:
        return None

    return RuleResult(
        rule_id      = "ioc_domain_match",
        attack_type  = "DNS Query to Known Malicious Domain",
        confidence   = 0.95,
        mitre_id     = "T1071.004",
        mitre_tactic = "Command and Control",
        suggestion   = (
            f"Block '{query}' at DNS resolver and firewall level. "
            "Identify which process made the query (check active connections at this timestamp). "
            "Check for follow-on connections to resolved IPs."
        ),
        risk_note    = (
            f"This machine queried '{query}' which matches IOC entry '{matched}'. "
            "C2 beacons, phishing droppers, and malware distribution infrastructure "
            "all rely on DNS as their first outbound communication."
        ),
        evidence = {
            "event_id":      3008,
            "QueryName":     query,
            "MatchedIOC":    matched,
            "QueryResults":  event.get("QueryResults", ""),
        },
    )


def check_ioc_ip(event: dict, ioc: IOCLoader, state: RuleState) -> Optional[RuleResult]:
    """
    Firewall Event 5156 — network connection to known malicious IP.
    """
    if event["event_id"] != 5156:
        return None
    dest_ip = event.get("DestAddress", "")
    matched = ioc.match_ip(dest_ip)
    if not matched:
        return None

    return RuleResult(
        rule_id      = "ioc_ip_connection",
        attack_type  = "Connection to Known Malicious IP",
        confidence   = 0.95,
        mitre_id     = "T1071.001",
        mitre_tactic = "Command and Control",
        suggestion   = (
            f"Block {dest_ip} at the firewall immediately. "
            f"Identify the application making the connection: '{event.get('Application', '?')}'. "
            "If the process is unexpected, assume C2 beacon and begin IR."
        ),
        risk_note    = (
            f"Outbound connection to {dest_ip} (matches IOC: {matched}). "
            "This IP is associated with known C2 infrastructure, botnets, or Tor exit nodes."
        ),
        evidence = {
            "event_id":    5156,
            "DestAddress": dest_ip,
            "DestPort":    event.get("DestPort", ""),
            "SrcAddress":  event.get("SrcAddress", ""),
            "Application": event.get("Application", ""),
            "MatchedIOC":  matched,
        },
    )


def check_ioc_process_name(event: dict, ioc: IOCLoader, state: RuleState) -> Optional[RuleResult]:
    """
    Event 4688 — Process creation with known-bad process name.
    """
    if event["event_id"] != 4688:
        return None
    proc    = event.get("NewProcessName", "")
    matched = ioc.match_process(proc)
    if not matched:
        return None

    return RuleResult(
        rule_id      = "ioc_process_name",
        attack_type  = f"Known Attack Tool Executed: {matched}",
        confidence   = 0.90,
        mitre_id     = "T1588.002",
        mitre_tactic = "Resource Development",
        suggestion   = (
            f"Terminate process '{proc}' immediately. "
            "Identify how it arrived on disk (parent process, download source). "
            "Check for lateral movement or credential access activity in surrounding events."
        ),
        risk_note    = (
            f"'{matched}' is a known offensive security tool or malware. "
            "Its presence on a production machine is almost certainly malicious."
        ),
        evidence = {
            "event_id":       4688,
            "NewProcessName": proc,
            "MatchedIOC":     matched,
            "CommandLine":    _snip(event.get("CommandLine", "")),
            "ParentProcess":  event.get("ParentProcessName", ""),
            "SubjectUser":    event.get("SubjectUserName", ""),
        },
    )


def check_ioc_process_chain(event: dict, ioc: IOCLoader, state: RuleState) -> Optional[RuleResult]:
    """
    Event 4688 — Parent->child process relationship matches IOC chain list.
    e.g. winword.exe -> powershell.exe = macro execution.
    """
    if event["event_id"] != 4688:
        return None
    parent  = event.get("ParentProcessName", "")
    child   = event.get("NewProcessName", "")
    reason  = ioc.match_chain(parent, child)
    if not reason:
        return None

    import os
    parent_name = os.path.basename(parent)
    child_name  = os.path.basename(child)

    return RuleResult(
        rule_id      = "ioc_process_chain",
        attack_type  = f"Suspicious Process Chain: {parent_name} -> {child_name}",
        confidence   = 0.95,
        mitre_id     = "T1059",
        mitre_tactic = "Execution",
        suggestion   = (
            f"Investigate why '{parent_name}' spawned '{child_name}'. "
            f"Capture the full command line. "
            "If a document/macro was involved, quarantine it and scan for similar files."
        ),
        risk_note    = (
            f"'{parent_name}' spawning '{child_name}' matches a known attack pattern: {reason}. "
            "This chain rarely appears in legitimate operations."
        ),
        evidence = {
            "event_id":       4688,
            "ParentProcess":  parent,
            "NewProcess":     child,
            "CommandLine":    _snip(event.get("CommandLine", "")),
            "SubjectUser":    event.get("SubjectUserName", ""),
            "chain_reason":   reason,
        },
    )


# ─────────────────────────────────────────────────────────────────────────────
# ── NETWORK DISCOVERY ────────────────────────────────────────────────────────
# ─────────────────────────────────────────────────────────────────────────────

def check_inbound_port_scan(event: dict, ioc: IOCLoader, state: RuleState) -> Optional[RuleResult]:
    """
    Events 5156 / 5157 — Windows Filtering Platform connection permitted or blocked.

    A port scan shows up as many inbound connection events from the same source
    IP to many different destination ports within a short window.

    Requires "Filtering Platform Connection" auditing to be enabled:
        auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:enable

    Run the above in an Administrator command prompt once — it persists across reboots.

    5156 = connection permitted (open ports — scanner found something)
    5157 = connection blocked   (closed/filtered ports — the bulk of a scan)
    """
    if event["event_id"] not in (5156, 5157):
        return None

    # Only track inbound attempts (the scanner is probing us, not us scanning out).
    # Windows WFP encodes direction as a resource string:
    #   %%14592 = Inbound   %%14593 = Outbound
    # We check for both the raw code and the formatted English string.
    direction = event.get("Direction", event.get("direction", ""))
    if direction:
        is_inbound = ("14592" in direction) or ("inbound" in direction.lower())
        if not is_inbound:
            return None

    # WFP field names as they appear in the raw EventData XML
    src_ip   = (event.get("SourceAddress") or event.get("sourceaddress") or "").strip()
    dst_port = (event.get("DestPort") or event.get("destport") or "").strip()

    # Skip loopback, broadcast, unresolved
    if not src_ip or src_ip in ("-", "0.0.0.0", "::", "::1", "127.0.0.1"):
        return None
    if not dst_port or dst_port == "-":
        return None

    # Sliding-window count: how many distinct destination ports from this source?
    total, distinct_ports = state.record(f"portscan:{src_ip}", dst_port)

    # Windows only generates 5156 (permitted) for OPEN ports — closed-port RSTs
    # are handled by the kernel TCP stack before WFP can log them (no 5157).
    # A desktop typically has 3 open ports (135 DCOM, 139 NetBIOS, 445 SMB).
    # Any TCP connect scan of 1-5000 ports will hit all three, so threshold=3
    # reliably catches a scan while being too specific to fire on normal browsing
    # (which hits one service at a time, not 3 distinct ports in rapid succession).
    _THRESHOLD = 3    # distinct open ports accessed from same source in 60s

    if distinct_ports >= _THRESHOLD:
        if not state.check_and_record_alert(f"portscan:{src_ip}"):
            return None   # suppress duplicate alerts within the same burst
        return RuleResult(
            rule_id      = "net_portscan",
            attack_type  = "Port Scan",
            confidence   = 0.90,
            mitre_id     = "T1046",
            mitre_tactic = "Discovery",
            suggestion   = (
                f"Block {src_ip} at the perimeter firewall immediately. "
                "Review which ports were found open (check 5156 events from same source). "
                "If this is an internal IP, isolate the machine — it may be compromised "
                "and performing internal reconnaissance."
            ),
            risk_note    = (
                f"{src_ip} probed {distinct_ports} distinct destination ports on this host "
                f"within 60 seconds ({total} total connection events). "
                "Systematic port scanning is reconnaissance to map exposed services "
                "before targeted exploitation."
            ),
            evidence = {
                "_event_count":   total,          # sets event_count on the alert
                "event_id":       event["event_id"],
                "src_ip":         src_ip,
                "distinct_ports": distinct_ports,
                "total_events":   total,
                "last_dst_port":  dst_port,
                "last_protocol":  event.get("Protocol", ""),
            },
        )
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Rule registry — ordered list of all active rules
# Add new rules here. Order matters for threshold rules that share state keys.
# ─────────────────────────────────────────────────────────────────────────────


def check_security_log_cleared(event: dict, ioc: IOCLoader, state: RuleState) -> Optional[RuleResult]:
    """
    Event 1102 — Security audit log was cleared.
    This is almost always an attacker covering their tracks.
    """
    if event["event_id"] != 1102:
        return None
    return RuleResult(
        rule_id      = "security_log_cleared",
        attack_type  = "Security Log Cleared",
        confidence   = 0.95,
        mitre_id     = "T1070.001",
        mitre_tactic = "Defense Evasion",
        suggestion   = (
            "Immediately investigate who cleared the log (SubjectUserName field). "
            "Check SIEM/backup logs for events prior to the clear. "
            "Consider enabling log forwarding to a remote syslog server."
        ),
        risk_note    = (
            "Clearing the security log is a classic attacker technique to destroy "
            "forensic evidence after lateral movement or exfiltration."
        ),
        evidence={
            "event_id":    1102,
            "SubjectUser": event.get("SubjectUserName", event.get("subjectusername", "")),
            "computer":    event.get("computer", ""),
            "timestamp":   event.get("timestamp", ""),
        },
    )


def check_scheduled_task_any(event: dict, ioc: IOCLoader, state: RuleState) -> Optional[RuleResult]:
    """
    Event 4698 — Any new scheduled task created.
    Low confidence (tasks are common) but worth logging for visibility.
    The check_scheduled_task_suspicious rule fires with higher confidence
    when the task content looks malicious.
    """
    if event["event_id"] != 4698:
        return None
    return RuleResult(
        rule_id      = "scheduled_task_created",
        attack_type  = "Scheduled Task Created",
        confidence   = 0.75,
        mitre_id     = "T1053.005",
        mitre_tactic = "Persistence",
        suggestion   = (
            f"Review task '{event.get('TaskName', '?')}' in Task Scheduler. "
            "Confirm this task was authorized and check the action executable."
        ),
        risk_note    = (
            "Scheduled tasks are frequently abused for persistence. "
            "Verify the creator and the task action."
        ),
        evidence={
            "event_id":    4698,
            "TaskName":    event.get("TaskName", ""),
            "SubjectUser": event.get("SubjectUserName", ""),
            "computer":    event.get("computer", ""),
        },
    )



ALL_RULES = [
    # Credential Access
    check_kerberoasting,
    check_asrep_roasting,
    check_brute_force,
    check_password_spray,
    # Execution
    check_ps_download_cradle,
    check_ps_encoded,
    check_ps_reflection,
    # Persistence
    check_psexec_service,
    check_new_service_suspicious_path,
    check_wmi_persistence,
    check_scheduled_task_any,
    check_scheduled_task_suspicious,
    # Privilege Escalation
    check_privileged_group_add,
    # Defense Evasion / Impact
    check_security_log_cleared,
    check_audit_policy_changed,
    check_defender_disabled,
    check_shadow_copy_deletion,
    # Network discovery
    check_inbound_port_scan,
    # IOC matching (run last — broadest checks)
    check_ioc_domain,
    check_ioc_ip,
    check_ioc_process_name,
    check_ioc_process_chain,
]

