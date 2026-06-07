# -*- coding: utf-8 -*-
"""
FLARE v0.6 - IOC Loader
─────────────────────
Loads all four IOC files at startup and pre-indexes them for O(1) lookup.
All lookups are case-insensitive. CIDR ranges are supported for IPs.
Wildcard domains (*.evil.com) are supported.

Calling reload() hot-swaps the IOC lists without restarting the agent.
"""

import ipaddress
import logging
import os
import re
import threading
from pathlib import Path
from typing import Optional

log = logging.getLogger("ioc_loader")

# Default IOC directory — two levels up from this file (Flare-Final-V2/ioc/)
DEFAULT_IOC_DIR = Path(__file__).parent.parent / "ioc"


class IOCLoader:
    """
    Thread-safe IOC list manager.

    Usage:
        ioc = IOCLoader()          # loads from default ioc/ directory
        ioc = IOCLoader("/path")   # loads from custom directory

        ioc.match_domain("evil.ddns.net")   -> "*.ddns.net" or None
        ioc.match_ip("185.220.101.5")       -> "185.220.101.0/24" or None
        ioc.match_process("mimikatz.exe")   -> "mimikatz.exe" or None
        ioc.match_chain("winword.exe", "powershell.exe") -> reason str or None

        ioc.reload()   # re-read all files from disk (hot-swap)
    """

    def __init__(self, ioc_dir: Optional[str] = None):
        self._dir   = Path(ioc_dir) if ioc_dir else DEFAULT_IOC_DIR
        self._lock  = threading.RLock()

        # Populated by _load()
        self._domains:        set   = set()   # exact lowercase domains
        self._domain_suffixes: set  = set()   # from *.foo.com → "foo.com"
        self._ip_networks:    list  = []      # list of ipaddress.IPv4Network
        self._ip_exact:       set   = set()   # exact IP strings
        self._process_names:  set   = set()   # lowercase exe names
        self._process_chains: dict  = {}      # (parent.exe, child.exe) -> reason

        self._load()

    # ─────────────────────────────────────────────────────────────────────────
    # Public interface
    # ─────────────────────────────────────────────────────────────────────────

    def match_domain(self, query: str) -> Optional[str]:
        """Return the matched IOC entry string, or None."""
        q = query.lower().rstrip(".")
        with self._lock:
            if q in self._domains:
                return q
            for suffix in self._domain_suffixes:
                if q == suffix or q.endswith("." + suffix):
                    return f"*.{suffix}"
        return None

    def match_ip(self, ip_str: str) -> Optional[str]:
        """Return matched IP/CIDR string, or None."""
        ip_str = ip_str.strip()
        with self._lock:
            if ip_str in self._ip_exact:
                return ip_str
            try:
                addr = ipaddress.ip_address(ip_str)
                for net in self._ip_networks:
                    if addr in net:
                        return str(net)
            except ValueError:
                pass
        return None

    def match_process(self, process_path: str) -> Optional[str]:
        """Return matched process name (basename only), or None."""
        name = os.path.basename(process_path).lower()
        with self._lock:
            if name in self._process_names:
                return name
        return None

    def match_chain(self, parent_path: str, child_path: str) -> Optional[str]:
        """Return reason string if parent→child chain is in IOC list, else None."""
        parent = os.path.basename(parent_path).lower()
        child  = os.path.basename(child_path).lower()
        with self._lock:
            return self._process_chains.get((parent, child))

    def reload(self):
        """Re-read all IOC files from disk. Thread-safe hot-swap."""
        log.info("IOCLoader: reloading IOC files from %s", self._dir)
        self._load()

    @property
    def stats(self) -> dict:
        with self._lock:
            return {
                "domains":        len(self._domains) + len(self._domain_suffixes),
                "ip_ranges":      len(self._ip_networks) + len(self._ip_exact),
                "process_names":  len(self._process_names),
                "process_chains": len(self._process_chains),
            }

    # ─────────────────────────────────────────────────────────────────────────
    # Private loading
    # ─────────────────────────────────────────────────────────────────────────

    def _load(self):
        domains, suffixes = self._load_domains()
        ip_exact, ip_nets = self._load_ips()
        procs             = self._load_process_names()
        chains            = self._load_process_chains()

        with self._lock:
            self._domains         = domains
            self._domain_suffixes = suffixes
            self._ip_exact        = ip_exact
            self._ip_networks     = ip_nets
            self._process_names   = procs
            self._process_chains  = chains

        log.info(
            "IOCLoader: loaded — domains=%d  ips=%d  procs=%d  chains=%d",
            len(domains) + len(suffixes),
            len(ip_exact) + len(ip_nets),
            len(procs),
            len(chains),
        )

    def _iter_lines(self, filename: str):
        """Yield non-empty, non-comment lines from an IOC file."""
        path = self._dir / filename
        if not path.exists():
            log.warning("IOCLoader: %s not found — skipping", path)
            return
        with open(path, encoding="utf-8", errors="replace") as f:
            for raw in f:
                line = raw.split("#")[0].strip()  # strip inline comments
                if line:
                    yield line

    def _load_domains(self):
        exact    = set()
        suffixes = set()
        for line in self._iter_lines("ioc_domains.txt"):
            line = line.lower()
            if line.startswith("*."):
                suffixes.add(line[2:])  # store "ddns.net" from "*.ddns.net"
            else:
                exact.add(line)
        return exact, suffixes

    def _load_ips(self):
        exact    = set()
        networks = []
        for line in self._iter_lines("ioc_ips.txt"):
            try:
                if "/" in line:
                    networks.append(ipaddress.IPv4Network(line, strict=False))
                else:
                    ipaddress.ip_address(line)   # validate
                    exact.add(line)
            except ValueError:
                log.debug("IOCLoader: invalid IP entry skipped: %r", line)
        return exact, networks

    def _load_process_names(self):
        names = set()
        for line in self._iter_lines("ioc_process_names.txt"):
            names.add(line.lower())
        return names

    def _load_process_chains(self):
        chains = {}
        for line in self._iter_lines("ioc_process_chains.txt"):
            # Format: parent.exe -> child.exe   # optional reason
            m = re.match(r"^(\S+)\s*->\s*(\S+)", line)
            if m:
                parent = m.group(1).lower()
                child  = m.group(2).lower()
                # Capture everything after "->" as reason (already stripped of #comment)
                reason = line[m.end():].strip() or f"{parent} spawning {child}"
                chains[(parent, child)] = reason
        return chains
