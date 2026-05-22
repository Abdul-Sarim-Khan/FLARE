# -*- coding: utf-8 -*-
"""
FLARE v0.4 - Host Rule Engine
────────────────────────────
Subscribes to Windows Event Log channels in real-time, parses event XML,
runs ALL_RULES from rules.py, and queues AlertEvent proto messages.

Usage (from flare_agent.py):

    import queue, threading
    from host.host_engine import start as start_host_engine

    alert_q   = queue.Queue()
    stop_evt  = threading.Event()
    start_host_engine(alert_q, stop_evt)

    # alerts arrive as log_schema_pb2.AlertEvent objects
    alert = alert_q.get()

The engine runs entirely in background threads — start() returns immediately.
Call stop_evt.set() to shut down cleanly.
"""

import json
import logging
import os
import queue
import socket
import sys
import threading
import time
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# ── pywin32 — Windows Event Log API ──────────────────────────────────────────
try:
    import win32evtlog
    import win32event
    import win32con
    import pywintypes
    _WIN32_AVAILABLE = True
except ImportError:
    _WIN32_AVAILABLE = False

# ── Path setup ────────────────────────────────────────────────────────────────
# Allow importing both from the project root (host.rules) and from within
# the host/ directory (rules.py uses bare `from ioc_loader import IOCLoader`).
_HOST_DIR    = Path(__file__).parent
_PROJECT_DIR = _HOST_DIR.parent
for _p in (str(_PROJECT_DIR), str(_HOST_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from proto import log_schema_pb2 as pb  # noqa: E402

# ── Rule engine ───────────────────────────────────────────────────────────────
from host.ioc_loader import IOCLoader
from host.rules      import ALL_RULES, RuleState, RuleResult

log = logging.getLogger("host_engine")

# ─────────────────────────────────────────────────────────────────────────────
# Agent identity helpers
# ─────────────────────────────────────────────────────────────────────────────

def _client_id() -> str:
    return os.environ.get("COMPUTERNAME", socket.gethostname())

def _client_ip() -> str:
    try:
        server_url = os.environ.get("FLARE_SERVER_URL", "https://localhost:7331")
        from urllib.parse import urlparse
        host = urlparse(server_url).hostname or "localhost"
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((host, 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "0.0.0.0"

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

# ─────────────────────────────────────────────────────────────────────────────
# Confidence -> Severity mapping
# ─────────────────────────────────────────────────────────────────────────────

def _severity(confidence: float) -> pb.Severity:
    if confidence >= 0.95:
        return pb.SEVERITY_CRITICAL
    if confidence >= 0.85:
        return pb.SEVERITY_HIGH
    if confidence >= 0.75:
        return pb.SEVERITY_MEDIUM
    return pb.SEVERITY_LOW

# ─────────────────────────────────────────────────────────────────────────────
# XML parsing helpers
# ─────────────────────────────────────────────────────────────────────────────

def strip_namespaces(elem: ET.Element):
    """Remove namespaces from all tags in the element tree."""
    for el in elem.iter():
        if '}' in el.tag:
            el.tag = el.tag.split('}', 1)[1]


def _text(element: Optional[ET.Element]) -> str:
    if element is None:
        return ""
    return (element.text or "").strip()


def parse_event_xml(xml_str: str) -> dict:
    """
    Parse a Windows Event Log XML string into a normalized flat dict.

    Common fields always present:
        event_id     — integer string e.g. "4769"
        channel      — e.g. "Security"
        computer     — machine name
        timestamp    — ISO-8601 UTC string
        provider     — provider/source name

    Event-Data fields extracted by Name attribute or positional index
    as data_0, data_1, … for unnamed fields.

    Returns empty dict on parse error.
    """
    try:
        root = ET.fromstring(xml_str)
        strip_namespaces(root)
    except ET.ParseError as exc:
        log.debug("parse_event_xml: XML parse error: %s", exc)
        return {}

    result = {}

    # ── System section ────────────────────────────────────────────────────────
    sys_el = root.find(".//System")
    if sys_el is not None:
        provider_el = sys_el.find("Provider")
        result["provider"] = (
            provider_el.get("Name", "") if provider_el is not None else ""
        )
        eid_el = sys_el.find("EventID")
        eid_raw = _text(eid_el)
        try:
            result["event_id"] = int(eid_raw)
        except (ValueError, TypeError):
            result["event_id"] = eid_raw

        level_el = sys_el.find("Level")
        result["level"] = _text(level_el)

        channel_el = sys_el.find("Channel")
        result["channel"] = _text(channel_el)

        computer_el = sys_el.find("Computer")
        result["computer"] = _text(computer_el)

        time_el = sys_el.find("TimeCreated")
        if time_el is not None:
            result["timestamp"] = time_el.get("SystemTime", "")
        else:
            result["timestamp"] = ""

    # ── EventData section ─────────────────────────────────────────────────────
    data_el = root.find(".//EventData")
    if data_el is not None:
        for i, child in enumerate(data_el):
            local = child.tag
            if local == "Data":
                name = child.get("Name")
                val  = (child.text or "").strip()
                if name:
                    # Store under both the original Name and a lowercased key
                    result[name]              = val
                    result[name.lower()]      = val
                else:
                    result[f"data_{i}"]       = val

    # ── UserData section (used by some providers e.g. WMI) ───────────────────
    user_data_el = root.find(".//UserData")
    if user_data_el is not None:
        # Flatten all leaf text nodes under UserData
        for child in user_data_el.iter():
            tag = child.tag
            if child.text and child.text.strip():
                result.setdefault(tag, child.text.strip())
                result.setdefault(tag.lower(), child.text.strip())

    return result


# ─────────────────────────────────────────────────────────────────────────────
# AlertEvent builder
# ─────────────────────────────────────────────────────────────────────────────

def _build_alert(result: RuleResult, event: dict,
                 client_id: str, client_ip: str) -> pb.AlertEvent:
    ts = _now_iso()
    evt_ts = event.get("timestamp", ts)

    alert              = pb.AlertEvent()
    alert.alert_id     = str(uuid.uuid4())
    alert.timestamp    = ts
    alert.client_id    = client_id
    alert.client_ip    = client_ip
    alert.severity     = _severity(result.confidence)
    alert.track        = pb.TRACK_HOST
    alert.attack_type  = result.attack_type
    alert.confidence   = result.confidence

    # Detection window — for single-event rules both start/end = event timestamp
    alert.window_start = evt_ts
    alert.window_end   = ts
    alert.event_count  = int(result.evidence.get("_event_count", 1))

    # Evidence — serialize to JSON, exclude private keys (_*)
    evidence_clean = {k: v for k, v in result.evidence.items()
                      if not k.startswith("_")}
    alert.evidence     = json.dumps(evidence_clean, ensure_ascii=False)
    
    # Append the raw log string directly to the proto field
    alert.raw_log      = event.get("_raw_xml", "")

    # Rule-based enrichment
    alert.rule_id      = result.rule_id
    alert.mitre_id     = result.mitre_id
    alert.mitre_tactic = result.mitre_tactic
    alert.suggestion   = result.suggestion
    alert.risk_note    = result.risk_note

    return alert


# ─────────────────────────────────────────────────────────────────────────────
# Channel subscription worker
# ─────────────────────────────────────────────────────────────────────────────

# Map each channel name to the set of Event IDs we care about.
# Empty set = accept all events from that channel (e.g. PS operational).
# NOTE: Event 5156 (Filtering Platform Connection) is logged by
# "Microsoft-Windows-Security-Auditing" in the SECURITY channel — NOT in the
# Windows Firewall Advanced Security channel (which holds rules-change events
# in the 2004-2099 range).  Must also enable the audit policy on each endpoint:
#   auditpol /set /subcategory:"Filtering Platform Connection" /success:enable
_SUBSCRIPTIONS: dict[str, set] = {
    "Security": {
        1102,   # Security audit log cleared (defense evasion)
        4625,   # Failed logon
        4688,   # Process creation
        4698,   # Scheduled task created
        4719,   # Audit policy changed
        4728,   # Member added to global security group
        4732,   # Member added to local security group
        4756,   # Member added to universal security group
        4768,   # Kerberos AS request (AS-REP roasting)
        4769,   # Kerberos service ticket (Kerberoasting)
        5156,   # Filtering Platform: outbound connection allowed (IOC IP match)
    },
    "System": {
        7045,   # New service installed
    },
    "Microsoft-Windows-PowerShell/Operational": {
        4104,   # Script block logging
    },
    "Microsoft-Windows-DNS-Client/Operational": {
        3008,   # DNS query
    },
    "Microsoft-Windows-WMI-Activity/Operational": {
        5861,   # WMI permanent event subscription
    },
    "Microsoft-Windows-Windows Defender/Operational": {
        5001,   # Defender real-time protection disabled
        5010,   # Defender scanning disabled
        5012,   # Defender disabled
    },
}


class _ChannelWorker(threading.Thread):
    """
    Subscribes to one Windows Event Log channel using EvtSubscribe
    (future-events mode). On each event, parses XML and pushes to the
    shared processing queue for rule evaluation.
    """

    def __init__(
        self,
        channel:    str,
        event_ids:  set,
        proc_queue: queue.Queue,
        stop_event: threading.Event,
    ):
        super().__init__(name=f"HostEng-{channel.split('/')[-1]}", daemon=True)
        self._channel    = channel
        self._event_ids  = event_ids
        self._proc_queue = proc_queue
        self._stop       = stop_event

    def _callback(self, action, context, evt_handle):
        """
        Called by Windows on a background C thread when a new event arrives.
        We immediately process the handle and push the result to the queue.
        """
        if action == win32evtlog.EvtSubscribeActionDeliver:
            try:
                self._process_handle(evt_handle)
            except Exception as exc:
                log.debug("HostEngine: callback error: %s", exc)

    def run(self):
        if not _WIN32_AVAILABLE:
            log.error("HostEngine: pywin32 not available — cannot subscribe to %s",
                      self._channel)
            return

        log.info("HostEngine: subscribing to channel '%s'", self._channel)

        try:
            subscription = win32evtlog.EvtSubscribe(
                self._channel,
                win32evtlog.EvtSubscribeToFutureEvents,
                None,
                Callback=self._callback,
            )
        except Exception as exc:
            log.warning(
                "HostEngine: cannot subscribe to '%s': %s — skipping",
                self._channel, exc,
            )
            return

        log.info("HostEngine: live on '%s'", self._channel)

        try:
            while not self._stop.is_set():
                time.sleep(0.5)

        finally:
            try:
                win32evtlog.EvtClose(subscription)
            except Exception:
                pass
            log.info("HostEngine: unsubscribed from '%s'", self._channel)

    def _process_handle(self, evt_handle):
        """Render event XML and push to the processing queue if relevant."""
        try:
            xml_str = win32evtlog.EvtRender(evt_handle,
                                             win32evtlog.EvtRenderEventXml)
        except Exception as exc:
            log.debug("HostEngine: EvtRender failed: %s", exc)
            return

        event = parse_event_xml(xml_str)
        if not event:
            return
            
        event["_raw_xml"] = xml_str

        # Filter by Event ID if we have a filter list
        # event_id is already an int after parse_event_xml normalisation
        if self._event_ids:
            eid = event.get("event_id", 0)
            if eid not in self._event_ids:
                return

        # Fix 6: use put_nowait instead of put() — this callback runs on the
        # Windows COM thread; blocking here would deadlock the Event Log
        # subscription pump if the rule-worker consumer falls behind.
        try:
            self._proc_queue.put_nowait(event)
        except queue.Full:
            log.warning(
                "HostEngine: proc_queue full — dropping event EID=%s",
                event.get("event_id", "?"),
            )


# ─────────────────────────────────────────────────────────────────────────────
# Rule evaluation worker
# ─────────────────────────────────────────────────────────────────────────────

class _RuleWorker(threading.Thread):
    """
    Pulls parsed event dicts from the processing queue,
    runs ALL_RULES, and pushes AlertEvent protos to the alert queue.

    One instance is sufficient — rule evaluation is CPU-light.
    """

    def __init__(
        self,
        proc_queue:  queue.Queue,
        alert_queue: queue.Queue,
        stop_event:  threading.Event,
        ioc:         IOCLoader,
        state:       RuleState,
        counters:    dict,
    ):
        super().__init__(name="HostEng-RuleWorker", daemon=True)
        self._proc_q  = proc_queue
        self._alert_q = alert_queue
        self._stop    = stop_event
        self._ioc     = ioc
        self._state   = state
        self._counters = counters  # shared dict for stats reporting
        self._cid     = _client_id()
        self._cip     = _client_ip()

    def run(self):
        log.info("HostEngine: rule worker started (%d rules loaded)", len(ALL_RULES))
        while not self._stop.is_set():
            try:
                event = self._proc_q.get(timeout=0.5)
            except queue.Empty:
                continue

            self._evaluate(event)

    def _evaluate(self, event: dict):
        for rule_fn in ALL_RULES:
            try:
                result: Optional[RuleResult] = rule_fn(event, self._ioc, self._state)
            except Exception as exc:
                log.error("HostEngine: rule %s raised: %s", rule_fn.__name__, exc,
                          exc_info=True)
                result = None

            if result is None:
                continue

            log.info(
                "HostEngine: RULE HIT — %s | conf=%.2f | eid=%s",
                result.rule_id, result.confidence, event.get("event_id", "?"),
            )

            # Track IOC vs threshold hits for heartbeat stats
            is_ioc = result.rule_id.startswith("ioc_")
            if is_ioc:
                self._counters["ioc_matches"] = self._counters.get("ioc_matches", 0) + 1
            else:
                self._counters["rule_hits"] = self._counters.get("rule_hits", 0) + 1

            alert = _build_alert(result, event, self._cid, self._cip)
            try:
                self._alert_q.put_nowait(alert)
            except queue.Full:
                log.warning("HostEngine: alert queue full — dropping alert %s",
                            result.rule_id)


# ─────────────────────────────────────────────────────────────────────────────
# Stub mode (non-Windows development)
# ─────────────────────────────────────────────────────────────────────────────

class _StubWorker(threading.Thread):
    """
    Used when pywin32 is not available (e.g. running tests on Linux/Mac).
    Sits idle and logs a warning. No events are produced.
    """

    def __init__(self, stop_event: threading.Event):
        super().__init__(name="HostEng-Stub", daemon=True)
        self._stop = stop_event

    def run(self):
        log.warning(
            "HostEngine: running in STUB mode — pywin32 unavailable. "
            "No Windows events will be collected."
        )
        self._stop.wait()
        log.info("HostEngine: stub stopped.")


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

# Module-level shared counters — readable by flare_agent.py for heartbeats
_counters: dict = {
    "ioc_matches": 0,
    "rule_hits":   0,
}


def get_counters() -> dict:
    """
    Return a snapshot of rule-engine statistics since agent start.

    Returns:
        {
            "ioc_matches": int,  # IOC list hits (domain / IP / process name / chain)
            "rule_hits":   int,  # threshold-based rule firings
        }
    """
    return dict(_counters)


def start(
    alert_queue:  queue.Queue,
    stop_event:   threading.Event,
    ioc_dir:      Optional[str] = None,
) -> None:
    """
    Start the host rule engine in background threads.

    Args:
        alert_queue:  Shared queue — AlertEvent proto objects are placed here.
        stop_event:   Set this to request a clean shutdown of all threads.
        ioc_dir:      Optional path to the IOC file directory.
                      Defaults to <project-root>/ioc/

    Returns immediately. All threads are daemon threads and will not block
    the interpreter from exiting.
    """
    if not _WIN32_AVAILABLE:
        log.warning("HostEngine: pywin32 not available — starting in stub mode")
        _StubWorker(stop_event).start()
        return

    log.info("HostEngine: initialising IOC loader …")
    ioc = IOCLoader(ioc_dir)
    log.info("HostEngine: IOC stats — %s", ioc.stats)

    state      = RuleState()
    proc_queue = queue.Queue(maxsize=2000)

    # One channel worker per subscription
    for channel, event_ids in _SUBSCRIPTIONS.items():
        _ChannelWorker(channel, event_ids, proc_queue, stop_event).start()

    # Single rule evaluation worker
    _RuleWorker(
        proc_queue=proc_queue,
        alert_queue=alert_queue,
        stop_event=stop_event,
        ioc=ioc,
        state=state,
        counters=_counters,
    ).start()

    log.info(
        "HostEngine: started — %d channels, %d rules, IOC: %s",
        len(_SUBSCRIPTIONS),
        len(ALL_RULES),
        ioc.stats,
    )
