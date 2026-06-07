# -*- coding: utf-8 -*-
"""
FLARE v0.6 — Server Host Agent (Windows Service)
─────────────────────────────────────────────────
Runs the FLARE endpoint agent on the server machine itself, so the server host
is protected alongside its clients.

Key differences from the client flare_service.py:
  • Connects to https://localhost:7331 (no beacon needed)
  • Skips the flow collector and network inference to avoid a feedback loop
    where the agent captures its own FLARE server traffic
  • Auto-provisions its own mTLS client certificate on first start via the
    server's /api/provision endpoint (token from FLARE_PROVISION_TOKEN env var)

Usage (run as Administrator from the server\\ directory):
    python flare_server_agent_service.py install     Install the service
    python flare_server_agent_service.py start       Start the installed service
    python flare_server_agent_service.py stop        Stop the running service
    python flare_server_agent_service.py restart     Stop then start
    python flare_server_agent_service.py remove      Uninstall the service
    python flare_server_agent_service.py status      Print current service state
    python flare_server_agent_service.py debug       Run in foreground (Ctrl-C to stop)

Configuration:
    All settings are read from server_agent.env in this directory.
    Required keys (written by generate_pki.py or setup scripts):
        FLARE_CA_CERT        path to ca.crt
        FLARE_CLIENT_CERT    path to server-agent's client.crt  (auto-provisioned)
        FLARE_CLIENT_KEY     path to server-agent's client.key  (auto-provisioned)
    Optional:
        FLARE_PROVISION_TOKEN  provisioning token (default: "flare")
        FLARE_LOG_LEVEL        DEBUG / INFO / WARNING (default: INFO)

Log output:
    logs\\flare_server_agent.log   (rotated at 10 MB, keeps 3 backups)
    Windows Application Event Log  (start / stop / errors)

Requirements:
    pip install pywin32
    python <site-packages>/pywin32_postinstall.py -install   (once, as admin)
"""

import io
import logging
import logging.handlers
import os
import socket
import ssl
import sys
import threading
import time
import zipfile
from pathlib import Path
from urllib.parse import urlparse

# ── Path setup ────────────────────────────────────────────────────────────────
_SVC_DIR    = Path(__file__).resolve().parent
_CLIENT_DIR = _SVC_DIR.parent / "client"

# Agent lives in client\ — add it to the path so we can import it
if str(_CLIENT_DIR) not in sys.path:
    sys.path.insert(0, str(_CLIENT_DIR))
if str(_SVC_DIR) not in sys.path:
    sys.path.insert(0, str(_SVC_DIR))

# ── Service constants ─────────────────────────────────────────────────────────
SERVICE_NAME         = "FLAREServerAgent"
SERVICE_DISPLAY_NAME = "FLARE v0.6 Server Host Agent"
SERVICE_DESCRIPTION  = (
    "FLARE v0.6 endpoint agent running on the server host. "
    "Monitors Windows Event Logs for threats. Network capture is disabled "
    "to avoid analysing FLARE's own server traffic."
)
SERVER_URL   = "https://localhost:7331"
LOG_FILE     = _SVC_DIR / "logs" / "flare_server_agent.log"
ENV_FILE     = _SVC_DIR / "server_agent.env"
CERT_DIR     = _SVC_DIR / "certs" / "clients" / "server-agent"
LOG_MAX_BYTES = 10 * 1024 * 1024   # 10 MB per file
LOG_BACKUPS   = 3


# ── Logging setup ─────────────────────────────────────────────────────────────

def _setup_logging():
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    fmt  = logging.Formatter(
        "%(asctime)s  %(levelname)-8s  %(name)-20s  %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    root  = logging.getLogger()
    level = getattr(logging, os.environ.get("FLARE_LOG_LEVEL", "INFO").upper(), logging.INFO)
    root.setLevel(level)
    root.handlers.clear()

    fh = logging.handlers.RotatingFileHandler(
        str(LOG_FILE), maxBytes=LOG_MAX_BYTES, backupCount=LOG_BACKUPS, encoding="utf-8"
    )
    fh.setFormatter(fmt)
    root.addHandler(fh)

    try:
        ch = logging.StreamHandler(sys.stdout)
        ch.setFormatter(fmt)
        root.addHandler(ch)
    except Exception:
        pass


# ── Env file loader ───────────────────────────────────────────────────────────

def _load_env_file(path: Path):
    if not path.exists():
        return
    with open(path, encoding="utf-8-sig") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            key, val = key.strip(), val.strip()
            if key and val:
                os.environ[key] = val


# ── Certificate auto-provisioning ─────────────────────────────────────────────

def _provision_certs(log) -> bool:
    """
    Request a client cert bundle from the local FLARE server via /api/provision.
    Saves ca.crt, client.crt, and client.key into CERT_DIR.
    Returns True on success.
    """
    ca_cert = _SVC_DIR / "certs" / "ca.crt"
    token   = os.environ.get("FLARE_PROVISION_TOKEN", "flare")
    url     = f"{SERVER_URL}/api/provision?token={token}&client=server-agent"

    log.info("Provisioning server-agent cert from %s", url)

    try:
        ctx = ssl.create_default_context()
        if ca_cert.exists():
            ctx.load_verify_locations(str(ca_cert))
        else:
            # CA not yet present — skip verification for the bootstrap call only
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            log.warning("CA cert not found at %s — skipping server verification for provisioning", ca_cert)

        import urllib.request as _req
        resp = _req.urlopen(url, context=ctx, timeout=10)
        data = resp.read()
    except Exception as exc:
        log.error("Provisioning request failed: %s", exc)
        return False

    try:
        CERT_DIR.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            for name in zf.namelist():
                dest = CERT_DIR / Path(name).name
                dest.write_bytes(zf.read(name))
                log.info("  wrote %s", dest)
    except Exception as exc:
        log.error("Failed to unpack provisioned cert bundle: %s", exc)
        return False

    return True


def _ensure_certs(log) -> bool:
    """
    Ensure the server-agent has a client cert. Provisions from the server if
    any cert file is missing. Returns True if certs are ready.
    """
    client_crt = CERT_DIR / "client.crt"
    client_key = CERT_DIR / "client.key"

    if client_crt.exists() and client_key.exists():
        return True

    log.info("Server-agent certs not found — attempting auto-provisioning…")

    # Give the server a moment to be ready (it starts before this service)
    for attempt in range(1, 4):
        time.sleep(3)
        if _provision_certs(log):
            log.info("Server-agent cert provisioned successfully")
            return True
        log.warning("Provisioning attempt %d/3 failed — retrying…", attempt)

    log.error(
        "Could not provision server-agent certs. "
        "Make sure the FLARE server is running and FLARE_PROVISION_TOKEN is correct. "
        "You can also manually run:  python generate_pki.py --client server-agent"
    )
    return False


def _apply_cert_env():
    """Inject cert paths into the environment so flare_agent picks them up."""
    ca_cert    = _SVC_DIR / "certs" / "ca.crt"
    client_crt = CERT_DIR / "client.crt"
    client_key = CERT_DIR / "client.key"

    os.environ["FLARE_SERVER_URL"]  = SERVER_URL
    if ca_cert.exists():
        os.environ["FLARE_CA_CERT"] = str(ca_cert)
    if client_crt.exists():
        os.environ["FLARE_CLIENT_CERT"] = str(client_crt)
    if client_key.exists():
        os.environ["FLARE_CLIENT_KEY"] = str(client_key)


def _patch_agent(flare_agent, log) -> None:
    """Force the imported flare_agent module to use localhost.

    flare_agent reads os.environ at import time, but its agent.env loader runs
    at module level and unconditionally overwrites os.environ — including
    FLARE_SERVER_URL — which means any client-configured server IP will replace
    the localhost value we set in _apply_cert_env() before the import.

    After the import we reach into the module and fix the values directly so
    the agent connects to the local server regardless of what agent.env says.
    """
    import ssl as _ssl
    try:
        import requests as _req
        _has_req = True
    except ImportError:
        _has_req = False

    ca_cert    = str(_SVC_DIR / "certs" / "ca.crt")
    client_crt = str(CERT_DIR / "client.crt")
    client_key = str(CERT_DIR / "client.key")

    flare_agent.SERVER_URL   = SERVER_URL
    flare_agent.CA_CERT      = ca_cert
    flare_agent.CLIENT_CERT  = client_crt
    flare_agent.CLIENT_KEY   = client_key

    if _has_req and hasattr(flare_agent, "_session"):
        sess = flare_agent._session
        sess.verify = ca_cert if Path(ca_cert).exists() else True
        if Path(client_crt).exists() and Path(client_key).exists():
            sess.cert = (client_crt, client_key)
            flare_agent._TLS_MODE = "mtls"
        else:
            flare_agent._TLS_MODE = "no-client-cert"

    log.info(
        "Agent patched — SERVER_URL=%s  CA=%s  cert=%s",
        SERVER_URL, ca_cert, client_crt,
    )


# ═════════════════════════════════════════════════════════════════════════════
# Windows Service class
# ═════════════════════════════════════════════════════════════════════════════

try:
    import win32service
    import win32serviceutil
    import win32event
    import servicemanager
    _PYWIN32_OK = True
except ImportError:
    _PYWIN32_OK = False


if _PYWIN32_OK:

    class FLAREServerAgentService(win32serviceutil.ServiceFramework):
        _svc_name_         = SERVICE_NAME
        _svc_display_name_ = SERVICE_DISPLAY_NAME
        _svc_description_  = SERVICE_DESCRIPTION

        def __init__(self, args):
            win32serviceutil.ServiceFramework.__init__(self, args)
            self._win32_stop  = win32event.CreateEvent(None, 0, 0, None)
            self._stop_event  = threading.Event()
            self._agent_thread = None

        def SvcStop(self):
            log = logging.getLogger("flare_server_agent_svc")
            log.info("Service stop requested")
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            self._stop_event.set()
            win32event.SetEvent(self._win32_stop)

        def SvcDoRun(self):
            _load_env_file(ENV_FILE)
            _setup_logging()
            log = logging.getLogger("flare_server_agent_svc")

            servicemanager.LogInfoMsg(f"{SERVICE_DISPLAY_NAME} starting")
            log.info("=" * 60)
            log.info("%s starting", SERVICE_DISPLAY_NAME)
            log.info("  Log file : %s", LOG_FILE)
            log.info("  Env file : %s", ENV_FILE)
            log.info("  PID      : %d", os.getpid())
            log.info("  Server   : %s  (local — no beacon)", SERVER_URL)
            log.info("  Net cap  : DISABLED (server host — feedback loop prevention)")
            log.info("=" * 60)

            # Ensure this host has a client cert before importing the agent
            _ensure_certs(log)
            _apply_cert_env()

            try:
                import flare_agent
                # Force localhost URL — agent.env overwrites os.environ at import
                # time so we must patch the module globals after the import.
                _patch_agent(flare_agent, log)
            except Exception as exc:
                log.exception("Failed to import flare_agent: %s", exc)
                servicemanager.LogErrorMsg(f"{SERVICE_DISPLAY_NAME}: import failed — {exc}")
                return

            self._agent_thread = threading.Thread(
                target=self._run_agent,
                args=(flare_agent,),
                name="FLAREServerAgentMain",
                daemon=True,
            )
            self._agent_thread.start()

            while True:
                rc = win32event.WaitForSingleObject(self._win32_stop, 5000)
                if rc == win32event.WAIT_OBJECT_0:
                    break
                if not self._agent_thread.is_alive():
                    log.error("Agent thread died unexpectedly — stopping service")
                    servicemanager.LogErrorMsg(f"{SERVICE_DISPLAY_NAME}: agent thread died unexpectedly")
                    break

            if self._agent_thread and self._agent_thread.is_alive():
                log.info("Waiting for agent thread to finish…")
                self._agent_thread.join(timeout=30)
                if self._agent_thread.is_alive():
                    log.warning("Agent thread did not finish in 30 s — forcing exit")

            servicemanager.LogInfoMsg(f"{SERVICE_DISPLAY_NAME} stopped")
            log.info("%s stopped", SERVICE_DISPLAY_NAME)

        def _run_agent(self, flare_agent):
            log = logging.getLogger("flare_server_agent_svc")
            try:
                # no_net_capture=True: skip flow collector + network inference
                # no_beacon=True: always on localhost, no discovery needed
                flare_agent.run(self._stop_event, no_net_capture=True, no_beacon=True)
            except Exception as exc:
                log.exception("Agent crashed: %s", exc)
                servicemanager.LogErrorMsg(f"{SERVICE_DISPLAY_NAME}: agent crashed — {exc}")
                self._stop_event.set()
                win32event.SetEvent(self._win32_stop)


# ═════════════════════════════════════════════════════════════════════════════
# Debug / status helpers
# ═════════════════════════════════════════════════════════════════════════════

def _run_debug():
    _load_env_file(ENV_FILE)
    _setup_logging()
    log = logging.getLogger("flare_server_agent_svc")
    log.info("Running in DEBUG mode (foreground, Ctrl-C to stop)")

    _ensure_certs(log)
    _apply_cert_env()

    import flare_agent
    # Force localhost URL — agent.env overwrites os.environ at import time
    _patch_agent(flare_agent, log)

    stop_event = threading.Event()
    t = threading.Thread(
        target=flare_agent.run,
        args=(stop_event,),
        kwargs={"no_net_capture": True, "no_beacon": True},
        daemon=True,
    )
    t.start()

    try:
        while t.is_alive():
            time.sleep(1)
    except KeyboardInterrupt:
        log.info("Ctrl-C received — stopping")
        stop_event.set()
        t.join(timeout=30)
    log.info("Debug run finished")


def _print_status():
    if not _PYWIN32_OK:
        print("pywin32 not installed — cannot query service status")
        return

    _STATE = {
        win32service.SERVICE_STOPPED:          "STOPPED",
        win32service.SERVICE_START_PENDING:    "START_PENDING",
        win32service.SERVICE_STOP_PENDING:     "STOP_PENDING",
        win32service.SERVICE_RUNNING:          "RUNNING",
        win32service.SERVICE_CONTINUE_PENDING: "CONTINUE_PENDING",
        win32service.SERVICE_PAUSE_PENDING:    "PAUSE_PENDING",
        win32service.SERVICE_PAUSED:           "PAUSED",
    }
    try:
        scm    = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_CONNECT)
        svc    = win32service.OpenService(scm, SERVICE_NAME, win32service.SERVICE_QUERY_STATUS)
        status = win32service.QueryServiceStatus(svc)
        state  = _STATE.get(status[1], f"UNKNOWN({status[1]})")
        win32service.CloseServiceHandle(svc)
        win32service.CloseServiceHandle(scm)
        print(f"  Service : {SERVICE_DISPLAY_NAME}")
        print(f"  Name    : {SERVICE_NAME}")
        print(f"  State   : {state}")
    except win32service.error as exc:
        if exc.winerror == 1060:
            print(f"  Service '{SERVICE_NAME}' is not installed.")
        else:
            print(f"  Error querying service: {exc}")


# ═════════════════════════════════════════════════════════════════════════════
# Entry point
# ═════════════════════════════════════════════════════════════════════════════

def _print_usage():
    print(f"""
  FLARE v0.6 Server Host Agent  —  {SERVICE_DISPLAY_NAME}

  Usage (run as Administrator from the server\\ directory):
    python flare_server_agent_service.py install     Install the service
    python flare_server_agent_service.py start       Start the service
    python flare_server_agent_service.py stop        Stop the service
    python flare_server_agent_service.py restart     Stop then start
    python flare_server_agent_service.py remove      Uninstall the service
    python flare_server_agent_service.py status      Show current service state
    python flare_server_agent_service.py debug       Run in foreground (Ctrl-C to stop)

  The service appears in services.msc as:
    "{SERVICE_DISPLAY_NAME}"

  Cert bundle (auto-provisioned on first start):
    {CERT_DIR}\\client.crt
    {CERT_DIR}\\client.key

  Log file:  {LOG_FILE}
""")


def _is_admin() -> bool:
    """Return True if the current process has Administrator privileges."""
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def _relaunch_as_admin():
    """Relaunch this script as Administrator via UAC prompt, then exit."""
    import ctypes
    script = os.path.abspath(__file__)
    # ShellExecute with 'runas' triggers the UAC elevation dialog
    ret = ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, f'"{script}"', None, 1
    )
    if ret <= 32:
        print(f"\n  ERROR: Could not elevate to Administrator (code {ret}).")
        input("  Press Enter to exit...")
    sys.exit(0)


def _interactive_menu():
    """Show a numbered menu when the script is double-clicked with no arguments."""
    menu = [
        ("install", "Install the service"),
        ("start",   "Start the service"),
        ("stop",    "Stop the service"),
        ("restart", "Restart the service"),
        ("remove",  "Uninstall the service"),
        ("status",  "Show current service state"),
        ("debug",   "Run in foreground (Ctrl-C to stop)"),
    ]

    print()
    print("  ╔══════════════════════════════════════════════╗")
    print("  ║   FLARE v0.6 — Server Host Agent             ║")
    print("  ╚══════════════════════════════════════════════╝")
    print()
    for i, (cmd, desc) in enumerate(menu, 1):
        print(f"    [{i}]  {desc}")
    print()
    print("    [0]  Exit")
    print()

    choice = input("  Select an option: ").strip()

    if choice == "0" or choice == "":
        sys.exit(0)

    try:
        idx = int(choice) - 1
        if not (0 <= idx < len(menu)):
            raise ValueError
    except ValueError:
        print(f"\n  Invalid choice: '{choice}'")
        input("  Press Enter to exit...")
        sys.exit(1)

    return menu[idx][0]


if __name__ == "__main__":
    # Service management always requires Administrator — elevate immediately if not.
    if not _is_admin():
        _relaunch_as_admin()

    if len(sys.argv) < 2:
        cmd = _interactive_menu()
        # Inject the chosen command as if it was passed on the command line
        sys.argv.append(cmd)
    else:
        cmd = sys.argv[1].lower()

    if cmd == "debug":
        _run_debug()
        input("\n  Press Enter to exit...")
        sys.exit(0)

    if cmd == "status":
        _print_status()
        input("\n  Press Enter to exit...")
        sys.exit(0)

    if not _PYWIN32_OK:
        print("ERROR: pywin32 is not installed.")
        print("  pip install pywin32")
        print("  python <site-packages>/pywin32_postinstall.py -install")
        input("\n  Press Enter to exit...")
        sys.exit(1)

    if cmd == "install":
        win32serviceutil.HandleCommandLine(FLAREServerAgentService)
        try:
            scm = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_ALL_ACCESS)
            svc = win32service.OpenService(scm, SERVICE_NAME, win32service.SERVICE_CHANGE_CONFIG)
            win32service.ChangeServiceConfig2(
                svc,
                win32service.SERVICE_CONFIG_DESCRIPTION,
                SERVICE_DESCRIPTION,
            )
            win32service.CloseServiceHandle(svc)
            win32service.CloseServiceHandle(scm)
            print(f"  Description set: {SERVICE_DESCRIPTION[:60]}…")
        except Exception as exc:
            print(f"  (Could not set description: {exc})")
        input("\n  Press Enter to exit...")
        sys.exit(0)

    win32serviceutil.HandleCommandLine(FLAREServerAgentService)
    input("\n  Press Enter to exit...")
