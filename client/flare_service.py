# -*- coding: utf-8 -*-
"""
FLARE v0.6 — Windows Service Wrapper
────────────────────────────────────
Wraps flare_agent.run() as a proper Windows service using pywin32 so the
agent starts automatically at boot, runs as SYSTEM, and survives logout.

Usage (run as Administrator):
    python flare_service.py install     Install the service (does not start it)
    python flare_service.py start       Start the installed service
    python flare_service.py stop        Stop the running service
    python flare_service.py restart     Stop then start
    python flare_service.py remove      Uninstall the service
    python flare_service.py status      Print current service state
    python flare_service.py debug       Run in foreground (Ctrl-C to stop)

After install, the service also appears in services.msc as "FLARE v0.6 Agent".

Configuration:
    The service inherits all Machine-scope environment variables set by
    setup\\3_configure.ps1 (FLARE_SERVER_URL, FLARE_NET_CSV, etc.).
    As a fallback it also reads agent.env in the same folder if present.

Log output:
    logs\\flare_agent.log   (rotated at 10 MB, keeps 3 backups)
    Windows Application Event Log  (start / stop / errors)

Requirements:
    pip install pywin32
    python <site-packages>/pywin32_postinstall.py -install   (once, as admin)
"""

import logging
import logging.handlers
import os
import sys
import threading
import time
from pathlib import Path

# ── Path setup ────────────────────────────────────────────────────────────────
_SVC_DIR = Path(__file__).resolve().parent
if str(_SVC_DIR) not in sys.path:
    sys.path.insert(0, str(_SVC_DIR))

# ── Service constants ─────────────────────────────────────────────────────────
SERVICE_NAME         = "FLAREAgent"
SERVICE_DISPLAY_NAME = "FLARE v0.6 Endpoint Agent"
SERVICE_DESCRIPTION  = (
    "FLARE v0.6 federated endpoint detection agent. "
    "Monitors Windows Event Logs and network flows for threats."
)
LOG_FILE   = _SVC_DIR / "logs" / "flare_agent.log"
ENV_FILE   = _SVC_DIR / "agent.env"
LOG_MAX_BYTES  = 10 * 1024 * 1024   # 10 MB per file
LOG_BACKUPS    = 3

# ── Logging setup (file + optional console) ───────────────────────────────────

def _setup_logging():
    """
    Route all loggers to a rotating file.
    Works both in service mode (no console) and debug mode (also prints).
    """
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

    fmt     = logging.Formatter(
        "%(asctime)s  %(levelname)-8s  %(name)-20s  %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    root    = logging.getLogger()
    level   = getattr(logging, os.environ.get("FLARE_LOG_LEVEL", "INFO").upper(), logging.INFO)
    root.setLevel(level)

    # Remove any handlers added before us (e.g. basicConfig from imports)
    root.handlers.clear()

    # Rotating file handler
    fh = logging.handlers.RotatingFileHandler(
        str(LOG_FILE),
        maxBytes=LOG_MAX_BYTES,
        backupCount=LOG_BACKUPS,
        encoding="utf-8",
    )
    fh.setFormatter(fmt)
    root.addHandler(fh)

    # Console handler (only useful in debug mode; ignored when no terminal)
    try:
        ch = logging.StreamHandler(sys.stdout)
        ch.setFormatter(fmt)
        root.addHandler(ch)
    except Exception:
        pass


# ── Env file loader ───────────────────────────────────────────────────────────

def _load_env_file(path: Path):
    """
    Load KEY=VALUE pairs from an env file into os.environ.
    Only sets a key if it is NOT already in the environment
    (Machine-scope variables from 3_configure.ps1 take priority).
    """
    if not path.exists():
        return
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                continue
            key, _, val = line.partition("=")
            key = key.strip()
            val = val.strip()
            if key and key not in os.environ:
                os.environ[key] = val


# ═════════════════════════════════════════════════════════════════════════════
# Windows Service class (only available when pywin32 is installed)
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

    class FLAREService(win32serviceutil.ServiceFramework):
        """pywin32 service that runs flare_agent.run() on a background thread."""

        _svc_name_         = SERVICE_NAME
        _svc_display_name_ = SERVICE_DISPLAY_NAME
        _svc_description_  = SERVICE_DESCRIPTION

        def __init__(self, args):
            win32serviceutil.ServiceFramework.__init__(self, args)
            # Win32 event used by SvcStop to wake the main service thread
            self._win32_stop = win32event.CreateEvent(None, 0, 0, None)
            # threading.Event passed into flare_agent.run()
            self._stop_event = threading.Event()
            self._agent_thread: threading.Thread | None = None

        # ── SCM calls this to request a stop ──────────────────────────────────
        def SvcStop(self):
            log = logging.getLogger("flare_service")
            log.info("Service stop requested")
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            # Signal the agent to shut down
            self._stop_event.set()
            # Wake SvcDoRun's WaitForSingleObject
            win32event.SetEvent(self._win32_stop)

        # ── SCM calls this to actually run the service ─────────────────────────
        def SvcDoRun(self):
            log = logging.getLogger("flare_service")

            # ── Log environment from file (fallback) ──────────────────────────
            _load_env_file(ENV_FILE)

            # ── Set up logging ─────────────────────────────────────────────────
            _setup_logging()
            log = logging.getLogger("flare_service")   # re-get after setup

            servicemanager.LogInfoMsg(f"{SERVICE_DISPLAY_NAME} starting")
            log.info("=" * 60)
            log.info("%s starting", SERVICE_DISPLAY_NAME)
            log.info("  Log file : %s", LOG_FILE)
            log.info("  Env file : %s (fallback)", ENV_FILE)
            log.info("  PID      : %d", os.getpid())
            log.info("=" * 60)

            # ── Import agent (inside SvcDoRun so logging is ready first) ──────
            try:
                import flare_agent
            except Exception as exc:
                log.exception("Failed to import flare_agent: %s", exc)
                servicemanager.LogErrorMsg(
                    f"{SERVICE_DISPLAY_NAME}: import failed — {exc}"
                )
                return

            # ── Run agent on a daemon thread so we can wait on win32 event ────
            self._agent_thread = threading.Thread(
                target=self._run_agent,
                args=(flare_agent,),
                name="FLAREAgentMain",
                daemon=True,
            )
            self._agent_thread.start()

            # ── Wait until stop is signalled (win32 event or agent crash) ─────
            while True:
                rc = win32event.WaitForSingleObject(self._win32_stop, 5000)
                if rc == win32event.WAIT_OBJECT_0:
                    break           # stop was requested
                if not self._agent_thread.is_alive():
                    log.error("Agent thread died unexpectedly — stopping service")
                    servicemanager.LogErrorMsg(
                        f"{SERVICE_DISPLAY_NAME}: agent thread died unexpectedly"
                    )
                    break

            # ── Wait for agent thread to finish cleanly (up to 30 s) ─────────
            if self._agent_thread and self._agent_thread.is_alive():
                log.info("Waiting for agent thread to finish…")
                self._agent_thread.join(timeout=30)
                if self._agent_thread.is_alive():
                    log.warning("Agent thread did not finish in 30 s — forcing exit")

            servicemanager.LogInfoMsg(f"{SERVICE_DISPLAY_NAME} stopped")
            log.info("%s stopped", SERVICE_DISPLAY_NAME)

        def _run_agent(self, flare_agent):
            """Target for the agent thread. Catches all exceptions."""
            log = logging.getLogger("flare_service")
            try:
                flare_agent.run(self._stop_event)
            except Exception as exc:
                log.exception("Agent crashed: %s", exc)
                servicemanager.LogErrorMsg(
                    f"{SERVICE_DISPLAY_NAME}: agent crashed — {exc}"
                )
                # Signal stop so SvcDoRun exits cleanly
                self._stop_event.set()
                win32event.SetEvent(self._win32_stop)


# ═════════════════════════════════════════════════════════════════════════════
# Debug mode (run in foreground without SCM)
# ═════════════════════════════════════════════════════════════════════════════

def _run_debug():
    """
    Run the agent in the foreground (no SCM / no service install needed).
    Useful for testing the service code path on a dev machine.
    Press Ctrl-C to stop.
    """
    _load_env_file(ENV_FILE)
    _setup_logging()
    log = logging.getLogger("flare_service")
    log.info("Running in DEBUG mode (foreground, Ctrl-C to stop)")

    import flare_agent

    stop_event = threading.Event()
    t = threading.Thread(target=flare_agent.run, args=(stop_event,), daemon=True)
    t.start()

    try:
        while t.is_alive():
            time.sleep(1)
    except KeyboardInterrupt:
        log.info("Ctrl-C received — stopping")
        stop_event.set()
        t.join(timeout=30)
    log.info("Debug run finished")


# ═════════════════════════════════════════════════════════════════════════════
# Status helper
# ═════════════════════════════════════════════════════════════════════════════

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
        scm = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_CONNECT)
        svc = win32service.OpenService(
            scm, SERVICE_NAME,
            win32service.SERVICE_QUERY_STATUS,
        )
        status = win32service.QueryServiceStatus(svc)
        state  = _STATE.get(status[1], f"UNKNOWN({status[1]})")
        win32service.CloseServiceHandle(svc)
        win32service.CloseServiceHandle(scm)
        print(f"  Service : {SERVICE_DISPLAY_NAME}")
        print(f"  Name    : {SERVICE_NAME}")
        print(f"  State   : {state}")
    except win32service.error as exc:
        if exc.winerror == 1060:   # ERROR_SERVICE_DOES_NOT_EXIST
            print(f"  Service '{SERVICE_NAME}' is not installed.")
        else:
            print(f"  Error querying service: {exc}")


# ═════════════════════════════════════════════════════════════════════════════
# Entry point
# ═════════════════════════════════════════════════════════════════════════════

def _print_usage():
    print(f"""
  FLARE v0.6 Windows Service  —  {SERVICE_DISPLAY_NAME}

  Usage (run as Administrator):
    python flare_service.py install     Install the service
    python flare_service.py start       Start the service
    python flare_service.py stop        Stop the service
    python flare_service.py restart     Stop then start
    python flare_service.py remove      Uninstall the service
    python flare_service.py status      Show current service state
    python flare_service.py debug       Run in foreground (Ctrl-C to stop)

  After install the service appears in services.msc as:
    "{SERVICE_DISPLAY_NAME}"

  Log file:  {LOG_FILE}
""")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        _print_usage()
        sys.exit(0)

    cmd = sys.argv[1].lower()

    # ── debug: run in foreground, no SCM needed ───────────────────────────────
    if cmd == "debug":
        _run_debug()
        sys.exit(0)

    # ── status: query SCM ─────────────────────────────────────────────────────
    if cmd == "status":
        _print_status()
        sys.exit(0)

    # ── All other commands require pywin32 + SCM ──────────────────────────────
    if not _PYWIN32_OK:
        print("ERROR: pywin32 is not installed.")
        print("  pip install pywin32")
        print("  python <site-packages>/pywin32_postinstall.py -install")
        sys.exit(1)

    # ── install: inject the description after HandleCommandLine does the work ──
    if cmd == "install":
        # Let win32serviceutil do the registry work first
        win32serviceutil.HandleCommandLine(FLAREService)

        # Then set the description (not supported by HandleCommandLine directly)
        try:
            scm = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_ALL_ACCESS)
            svc = win32service.OpenService(
                scm, SERVICE_NAME, win32service.SERVICE_CHANGE_CONFIG
            )
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
        sys.exit(0)

    # ── All other commands (start, stop, restart, remove) → delegate ──────────
    win32serviceutil.HandleCommandLine(FLAREService)