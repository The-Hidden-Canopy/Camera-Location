"""Network interface detection and low-level network operations for Windows"""

from __future__ import annotations
import atexit
import ipaddress
import os
import re
import signal
import socket
import subprocess
import struct
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Set, Tuple


# ─── Temporary-IP registry ────────────────────────────────────────────────
#
# Every secondary/temporary IP we add to an interface via netsh is recorded
# here as an (interface_name, ip) pair.  This is the single source of truth
# for "what netsh changes has this process made", so we can ALWAYS undo them
# even if a sweep is killed mid-flight, the app window is closed, or the
# process is taskkill'd.  Leaked secondary IPs leave stale on-link routes in
# the Windows routing table, which is what previously caused spurious
# multi-subnet pulls — so reliable teardown is critical, not best-effort.
#
# _NETSH_LOCK serialises ALL netsh add/delete calls process-wide: Windows
# misbehaves if two interface-modification commands run at once.
_TEMP_IPS: Set[Tuple[str, str]] = set()
_NETSH_LOCK = threading.RLock()


def _run_netsh(args: List[str]) -> bool:
    """Run a netsh command under the global lock. Returns True on rc==0."""
    with _NETSH_LOCK:
        try:
            result = subprocess.run(
                ["netsh"] + args,
                capture_output=True, text=True, timeout=10,
            )
            return result.returncode == 0
        except Exception:
            return False


def cleanup_temp_ips(interface_name: str = "") -> int:
    """Remove every temporary IP this process added (optionally just one
    interface's).  Safe to call repeatedly and from any thread/handler.

    Returns the number of addresses removed.  This is THE teardown entry
    point — called when a scan finishes, when it's stopped, on normal
    interpreter exit (atexit), and on SIGINT/SIGTERM.
    """
    with _NETSH_LOCK:
        targets = [(ifc, ip) for (ifc, ip) in _TEMP_IPS
                   if not interface_name or ifc == interface_name]
        removed = 0
        for ifc, ip in targets:
            ok_v4 = _run_netsh(["interface", "ipv4", "delete", "address", ifc, ip])
            # Older add path used "interface ip"; try that form too.
            ok_v = _run_netsh(["interface", "ip", "delete", "address", ifc, ip])
            _TEMP_IPS.discard((ifc, ip))
            if ok_v4 or ok_v:
                removed += 1
        return removed


_signal_handlers_installed = False


def install_signal_handlers() -> None:
    """Install SIGINT/SIGTERM handlers that clear netsh before exiting.

    Must be called from the main thread (signal limitation).  atexit covers
    normal exit and KeyboardInterrupt; signal handlers cover taskkill /
    Electron window close / service stop where atexit may not fire.
    """
    global _signal_handlers_installed
    if _signal_handlers_installed:
        return
    _signal_handlers_installed = True

    def _handler(signum, frame):
        # Clear every netsh change first, then exit hard so a half-done
        # sweep can't leave the interface in a modified state.
        try:
            cleanup_temp_ips()
        finally:
            os._exit(130 if signum == getattr(signal, "SIGINT", None) else 0)

    for signame in ("SIGINT", "SIGTERM", "SIGBREAK"):
        sig = getattr(signal, signame, None)
        if sig is not None:
            try:
                signal.signal(sig, _handler)
            except (ValueError, OSError):
                pass  # not main thread / unsupported — atexit still covers us


# atexit fires on normal exit and on unhandled KeyboardInterrupt.
atexit.register(cleanup_temp_ips)


@dataclass
class NetworkInterface:
    name: str
    ip: str           # primary (best) IP
    netmask: str
    cidr: str
    mac: str
    iface_type: str   # ethernet | wi-fi | virtual | loopback | unknown
    is_up: bool = True
    gateway: str = ""
    subnet: str = ""
    all_ips: List[str] = field(default_factory=list)       # all IPs on this adapter
    all_netmasks: List[str] = field(default_factory=list)  # matching netmasks

    @property
    def prefix_len(self) -> int:
        try:
            return ipaddress.IPv4Network(f"0.0.0.0/{self.netmask}", strict=False).prefixlen
        except Exception:
            return 24

    def all_subnets(self) -> List[str]:
        """Return CIDR for every IP on this adapter."""
        result = []
        for ip, mask in zip(self.all_ips, self.all_netmasks):
            if ip.startswith("169.254"):
                continue
            try:
                net = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
                result.append(str(net))
            except Exception:
                pass
        return result


def _best_ip(ips: List[str]) -> str:
    """Pick the most useful IP: prefer non-APIPA, non-loopback, lowest /8."""
    def score(ip: str) -> int:
        if ip.startswith("169.254"):   return 100
        if ip.startswith("127."):      return 90
        if ip.startswith("172.28."):   return 50   # WSL virtual
        return 0
    candidates = [ip for ip in ips if not ip.startswith("169.254") and not ip.startswith("127.")]
    if not candidates:
        candidates = ips
    return min(candidates, key=score) if candidates else ""


def get_interfaces() -> List[NetworkInterface]:
    """
    Parse all network interfaces including multi-homed adapters.
    Returns one NetworkInterface per physical adapter; all_ips / all_netmasks
    carry every secondary address so discover_local_subnets() sees them all.
    """
    # ── ipconfig /all ────────────────────────────────────────────────
    iface_data: dict = {}   # name -> {mac, description, dhcp, gateway,
                             #          ips: [(ip, mask)], ...}
    try:
        result = subprocess.run(
            ["ipconfig", "/all"],
            capture_output=True, text=True, timeout=10
        )
        current = None
        last_ip = None
        for line in result.stdout.splitlines():
            # New adapter section
            sec = re.match(r"^[A-Za-z].*adapter (.+):", line)
            if sec:
                current = sec.group(1)
                iface_data[current] = {"ips": [], "masks": [], "gateway": "", "mac": "", "description": "", "dhcp": ""}
                last_ip = None
                continue
            if current is None:
                continue

            # Collect every IPv4 address (there can be many on multi-homed adapters).
            # Skip "Autoconfiguration IPv4 Address" so APIPA never becomes primary.
            ip_m = re.match(r"\s+IPv4 Address[.\s]+:\s+(\d+\.\d+\.\d+\.\d+)", line)
            if ip_m and "autoconfiguration" not in line.lower():
                last_ip = ip_m.group(1).strip().rstrip("(Preferred)")
                iface_data[current]["ips"].append(last_ip)
                continue

            mask_m = re.match(r"\s+Subnet Mask[.\s]+:\s+(\d+\.\d+\.\d+\.\d+)", line)
            if mask_m:
                iface_data[current]["masks"].append(mask_m.group(1))
                continue

            # Accept Windows hyphen, colon, or bare 12-hex MAC formats.
            mac_m = re.match(r"\s+Physical Address[.\s]+:\s+([0-9A-Fa-f:-]{17}|[0-9A-Fa-f]{12})", line)
            if mac_m and not iface_data[current]["mac"]:
                raw = mac_m.group(1).lower()
                if len(raw) == 12:
                    mac = ":".join(raw[i:i + 2] for i in range(0, 12, 2))
                else:
                    mac = raw.replace("-", ":")
                # Ignore broadcast / invalid placeholder MACs.
                if mac not in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
                    iface_data[current]["mac"] = mac
                continue

            desc_m = re.match(r"\s+Description[.\s]+:\s+(.+)", line)
            if desc_m and not iface_data[current]["description"]:
                iface_data[current]["description"] = desc_m.group(1).strip()
                continue

            gw_m = re.match(r"\s+Default Gateway[.\s]+:\s*(.+)", line)
            if gw_m and not iface_data[current]["gateway"]:
                # ipconfig may list IPv6 first; grab the first IPv4 address.
                for token in gw_m.group(1).split():
                    if re.match(r"\d+\.\d+\.\d+\.\d+", token):
                        iface_data[current]["gateway"] = token
                        break
                continue

    except Exception:
        pass

    # Fallback gateway lookup from IPv4 routing table when ipconfig omits it
    # (common when the adapter has only an IPv6 gateway listed).
    route_gateways: dict = {}
    try:
        route_result = subprocess.run(
            ["route", "print", "-4"],
            capture_output=True, text=True, timeout=10
        )
        for line in route_result.stdout.splitlines():
            # 0.0.0.0          0.0.0.0      192.168.1.1    192.168.1.107     35
            m = re.match(
                r"\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)",
                line,
            )
            if m:
                route_gateways[m.group(2)] = m.group(1)
    except Exception:
        pass

    interfaces = []
    for name, data in iface_data.items():
        ips = data["ips"]
        masks = data["masks"]
        if not ips:
            continue

        # Pad masks if ipconfig printed fewer than IPs (secondary IPs inherit same mask)
        while len(masks) < len(ips):
            masks.append(masks[-1] if masks else "255.255.255.0")

        primary_ip = _best_ip(ips)
        if not primary_ip:
            continue
        primary_idx = ips.index(primary_ip)
        primary_mask = masks[primary_idx]

        iface_type = classify_interface(name, data["description"])
        try:
            subnet = str(ipaddress.IPv4Network(f"{primary_ip}/{primary_mask}", strict=False).network_address)
        except Exception:
            subnet = "unknown"
        try:
            prefix_len = ipaddress.IPv4Network(f"{primary_ip}/{primary_mask}", strict=False).prefixlen
        except Exception:
            prefix_len = 24

        gateway = data["gateway"] or route_gateways.get(primary_ip, "")
        interfaces.append(NetworkInterface(
            name=name,
            ip=primary_ip,
            netmask=primary_mask,
            cidr=f"{primary_ip}/{prefix_len}",
            mac=data["mac"],
            iface_type=iface_type,
            gateway=gateway,
            subnet=subnet,
            all_ips=ips,
            all_netmasks=masks,
        ))

    type_order = {"ethernet": 0, "wi-fi": 1, "unknown": 2, "virtual": 3, "loopback": 4}
    interfaces.sort(key=lambda i: type_order.get(i.iface_type, 3))
    return interfaces


def classify_interface(name: str, description: str = "") -> str:
    lower = (name + " " + description).lower()
    if "loopback" in lower:
        return "loopback"
    # Check virtual BEFORE ethernet since "vEthernet" contains "ethernet"
    if any(x in lower for x in ["hyper-v", "vmware", "virtual", "vethernet", "docker", "wsl", "vnic", "vpn", "tunnel", "venet"]):
        return "virtual"
    if any(x in lower for x in ["wi-fi", "wireless", "wlan", "802.11"]):
        return "wi-fi"
    # "ethernet" / "eth" / "local area" cover most adapters.
    # Also match "gigabit" and "gbe" for Realtek/Intel adapters whose descriptions
    # say "PCIe GbE Family Controller" or "Gigabit Network Connection" without the
    # word "ethernet" — these are always wired.
    if any(x in lower for x in ["ethernet", "eth", "local area", "rj45",
                                  "gigabit", "gbe", "10gbe", "2.5gbe", "10/100",
                                  "family controller", "network connection"]):
        return "ethernet"
    return "unknown"


_arp_lock = threading.Lock()

def get_arp_table() -> List[dict]:
    """Parse Windows ARP table."""
    entries = []
    if not _arp_lock.acquire(timeout=5):
        return entries   # another thread is already running arp -a
    try:
        result = subprocess.run(
            ["arp", "-a"],
            capture_output=True, text=True, timeout=8
        )
        for line in result.stdout.splitlines():
            # Match both formats:
            #   192.168.1.195         9c-8e-cd-3f-e3-98     dynamic
            #   192.168.1.1           74-24-9f-5d-f0-aa     dynamic   0x15
            m = re.match(
                r"\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F.-]+)\s+(\S+)(?:\s+(\S+))?",
                line, re.IGNORECASE
            )
            if m:
                raw_mac = m.group(2).lower()
                if "." in raw_mac:
                    # Cisco dotted notation: 1234.5678.9abc
                    mac = ":".join(raw_mac.replace(".", "")[i:i + 2] for i in range(0, 12, 2))
                else:
                    mac = raw_mac.replace("-", ":")
                if mac == "ff:ff:ff:ff:ff:ff" or mac == "00:00:00:00:00:00":
                    continue
                entries.append({
                    "ip": m.group(1),
                    "mac": mac,
                    "type": m.group(3),
                    "iface": m.group(4) or "",
                })
    except Exception:
        pass
    finally:
        _arp_lock.release()
    return entries


_PING_FAILURE_PHRASES = (
    "destination host unreachable",
    "request timed out",
    "general failure",
    "transmit failed",
    "could not find host",
    "ping request could not find",
    "host unreachable",
    "ttl expired in transit",
    "time exceeded",
)

def ping_host(ip: str, timeout: int = 2000) -> bool:
    """Ping a host. Returns True only when the target itself replied.

    Windows can print "Reply from <gateway>: Destination host unreachable."
    That satisfies a naive "Reply from" check but the *target* is dead.
    We reject any reply that contains a failure phrase so gateway-generated
    ICMP errors are not mistaken for live devices.
    """
    try:
        result = subprocess.run(
            ["ping", "-n", "1", "-w", str(timeout), ip],
            capture_output=True, text=True, timeout=timeout // 1000 + 2
        )
        out = result.stdout.lower()
        # Must have TTL (echo reply) or "Reply from" (Windows success)
        if "ttl=" not in out and "reply from" not in out:
            return False
        # Reject gateway-generated failure messages
        if any(phrase in out for phrase in _PING_FAILURE_PHRASES):
            return False
        # Extra guard: if the reply is from a different IP than the target,
        # it's a gateway-generated ICMP error (e.g. TTL exceeded, unreachable)
        reply_from_m = re.search(r"reply from\s+(\d+\.\d+\.\d+\.\d+)", out)
        if reply_from_m:
            reply_from_ip = reply_from_m.group(1)
            if reply_from_ip != ip:
                return False
        return True
    except Exception:
        return False


def add_temp_ip(interface_name: str, ip: str, netmask: str = "255.255.255.0") -> bool:
    """Add a temporary IP address to an interface (requires admin).

    On success the (interface, ip) pair is registered so cleanup_temp_ips()
    can always tear it down later, even on crash/kill.
    """
    ok = _run_netsh(["interface", "ip", "add", "address",
                     interface_name, ip, netmask])
    if ok:
        with _NETSH_LOCK:
            _TEMP_IPS.add((interface_name, ip))
    return ok


def remove_temp_ip(interface_name: str, ip: str) -> bool:
    """Remove a temporary IP address from an interface (requires admin)."""
    ok = _run_netsh(["interface", "ip", "delete", "address",
                     interface_name, ip])
    # Deregister regardless: if the address is already gone we still want it
    # out of the registry so cleanup doesn't keep retrying it.
    with _NETSH_LOCK:
        _TEMP_IPS.discard((interface_name, ip))
    return ok


def ip_to_subnet(ip: str, prefix: int = 24) -> str:
    """Get the subnet for an IP with the given prefix length (default /24).

    Accepts an optional prefix so callers that know the real netmask can
    produce the correct CIDR instead of hardcoding /24.
    """
    try:
        net = ipaddress.IPv4Network(f"{ip}/{prefix}", strict=False)
        return str(net)
    except Exception:
        parts = ip.split(".")
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"


# ─── Subnet Zone Management ───────────────────────────────────────────

def add_static_route(subnet: str, gateway: str, persistent: bool = False) -> bool:
    """Add a static route to a subnet via a gateway. Returns True on success."""
    try:
        cmd = ["route", "add", subnet, gateway]
        if persistent:
            cmd.insert(1, "-p")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return result.returncode == 0
    except Exception:
        return False


def remove_static_route(subnet: str, gateway: str) -> bool:
    """Remove a static route. Returns True on success."""
    try:
        result = subprocess.run(
            ["route", "delete", subnet, gateway],
            capture_output=True, text=True, timeout=10
        )
        return result.returncode == 0
    except Exception:
        return False


def add_secondary_ip(interface_name: str, ip: str, prefix_len: int = 24) -> bool:
    """Add a secondary IP address to an interface using Netsh. Returns True on success.

    On success the (interface, ip) pair is registered so cleanup_temp_ips()
    can always tear it down later, even on crash/kill.
    """
    ok = _run_netsh(["interface", "ipv4", "add", "address",
                     interface_name, ip, str(_prefix_len_to_mask(prefix_len))])
    if ok:
        with _NETSH_LOCK:
            _TEMP_IPS.add((interface_name, ip))
    return ok


def remove_secondary_ip(interface_name: str, ip: str) -> bool:
    """Remove a secondary IP address from an interface. Returns True on success."""
    ok = _run_netsh(["interface", "ipv4", "delete", "address",
                     interface_name, ip])
    # Deregister regardless so cleanup doesn't keep retrying an address
    # that is already gone.
    with _NETSH_LOCK:
        _TEMP_IPS.discard((interface_name, ip))
    return ok


def _prefix_len_to_mask(prefix_len: int) -> str:
    """Convert CIDR prefix length to dotted-decimal netmask."""
    mask = (0xffffffff >> (32 - prefix_len)) << (32 - prefix_len)
    return f"{(mask >> 24) & 0xff}.{(mask >> 16) & 0xff}.{(mask >> 8) & 0xff}.{mask & 0xff}"


def get_routes() -> List[dict]:
    """Get current IPv4 routing table."""
    routes = []
    try:
        result = subprocess.run(
            ["route", "print", "-4"],
            capture_output=True, text=True, timeout=10
        )
        for line in result.stdout.splitlines():
            # Match: 0.0.0.0          0.0.0.0      192.168.1.1    192.168.1.148    35
            m = re.match(
                r"\s*(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+)",
                line
            )
            if m:
                routes.append({
                    "destination": m.group(1),
                    "netmask": m.group(2),
                    "gateway": m.group(3),
                    "interface": m.group(4),
                    "metric": int(m.group(5)),
                })
    except Exception:
        pass
    return routes


def test_tcp_port(ip: str, port: int, timeout: float = 3.0) -> bool:
    """Test if a TCP port is reachable on a host."""
    import socket as _socket
    try:
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def discover_local_subnets(exclude_virtual: bool = True) -> List[str]:
    """Return subnets reachable from local interfaces + routing table, without any user input."""
    found: set = set()

    # 1. Subnets from local interfaces — use all_subnets() to handle multi-homed adapters
    for iface in get_interfaces():
        if exclude_virtual and iface.iface_type in ("virtual", "loopback"):
            continue
        for subnet_cidr in iface.all_subnets():
            try:
                net = ipaddress.IPv4Network(subnet_cidr, strict=False)
                if net.prefixlen >= 8:
                    found.add(str(net))
            except Exception:
                pass
        # Fallback to primary IP if all_subnets() is empty
        if not iface.all_subnets() and iface.ip and not iface.ip.startswith("169.254"):
            try:
                net = ipaddress.IPv4Network(f"{iface.ip}/{iface.netmask}", strict=False)
                if net.prefixlen >= 8:
                    found.add(str(net))
            except Exception:
                pass

    # 2. Directly connected routes from routing table
    try:
        for route in get_routes():
            dest = route["destination"]
            netmask = route["netmask"]
            gateway = route["gateway"]
            iface_ip = route["interface"]

            if dest in ("0.0.0.0", "255.255.255.255"):
                continue
            if dest.startswith(("224.", "239.", "127.")):
                continue

            # On-link: gateway matches the interface's own IP
            if gateway == iface_ip:
                try:
                    net = ipaddress.IPv4Network(f"{dest}/{netmask}", strict=False)
                    if net.prefixlen >= 8:
                        found.add(str(net))
                except Exception:
                    pass
    except Exception:
        pass

    return sorted(found)


def probe_subnet_connectivity(subnet: str, test_ports: List[int] = None) -> dict:
    """Probe a subnet for basic connectivity. Returns summary stats."""
    if test_ports is None:
        test_ports = [80, 554, 8000, 37777]

    base = ".".join(subnet.split(".")[:3])
    reachable = 0
    port_hits = {p: 0 for p in test_ports}
    found_ips = []

    # Quick ping sweep (first 20 IPs for speed)
    with ThreadPoolExecutor(max_workers=30) as executor:
        futures = {}
        for i in range(1, 20):
            ip = f"{base}.{i}"
            futures[executor.submit(ping_host, ip, 500)] = ip

        for future in as_completed(futures):
            ip = futures[future]
            try:
                if future.result():
                    reachable += 1
                    found_ips.append(ip)
            except Exception:
                pass

    # Test ports on found IPs
    for ip in found_ips:
        for port in test_ports:
            if test_tcp_port(ip, port, 1.0):
                port_hits[port] += 1

    return {
        "subnet": subnet,
        "reachable_hosts": reachable,
        "tested_range": f"{base}.1-{base}.20",
        "port_hits": port_hits,
        "found_ips": found_ips,
    }


# ─── Subnet Sniffer ───────────────────────────────────────────────────
# Inspired by Wireshark: detect subnets from live traffic rather than
# relying on pre-configured lists.  Two layers:
#   1. Raw IP socket with SIO_RCVALL (Windows admin required) — sees every
#      packet crossing the interface, including cameras on foreign VLANs
#      that happen to bridge to this segment.
#   2. ARP-table poller (no admin) — catches anything that resolves at L2,
#      which covers DHCP-assigned cameras that haven't been configured yet.
# When a new /24 is first seen either way, on_new_subnet fires exactly once.

@dataclass
class SniffedSubnet:
    subnet: str
    first_seen_ip: str
    source: str   # "packet" | "arp" | "route"


class SubnetSniffer:
    """Detect subnets from raw traffic and ARP table changes.

    Only promotes RFC1918 private addresses (10/8, 172.16/12, 192.168/16)
    and link-local (169.254/16, treated as orphan signal only).  Public
    internet destination addresses are never promoted to scan targets —
    normal browsing traffic would otherwise queue arbitrary /24 scans and
    risk adding secondary IPs for public subnets.
    """

    _SKIP_PREFIXES = ("0.", "127.", "224.", "239.", "240.", "255.")

    def __init__(self):
        self._known: set = set()
        self._lock = threading.Lock()
        self._running = False
        self._threads: List[threading.Thread] = []
        self.on_new_subnet: Optional[Callable[[SniffedSubnet], None]] = None

    # ── Public API ──────────────────────────────────────────────────

    def seed(self, subnets: List[str]):
        """Pre-mark subnets as already known so they don't trigger callbacks.
        Accepts both CIDR (192.168.1.0/24) and bare IPs (192.168.1.5).
        All inputs are normalized to /24 CIDR for consistent matching."""
        normalized = set()
        for s in subnets:
            if "/" in s:
                normalized.add(s)
            else:
                # Bare IP → convert to /24
                parts = s.split(".")
                if len(parts) == 4:
                    normalized.add(f"{parts[0]}.{parts[1]}.{parts[2]}.0/24")
                else:
                    normalized.add(s)
        with self._lock:
            self._known.update(normalized)

    def start(self, iface_ip: str = ""):
        self._running = True
        # Raw packet capture (needs admin; silently degrades otherwise)
        t1 = threading.Thread(target=self._capture_raw, args=(iface_ip,), daemon=True)
        # ARP poller (always works)
        t2 = threading.Thread(target=self._poll_arp, daemon=True)
        self._threads = [t1, t2]
        t1.start()
        t2.start()

    def stop(self):
        self._running = False
        for t in self._threads:
            t.join(timeout=3)

    # ── Internal ────────────────────────────────────────────────────

    def _report(self, ip: str, source: str):
        if any(ip.startswith(p) for p in self._SKIP_PREFIXES):
            return
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return
        # Only auto-promote RFC1918 private space.  Public internet addresses
        # (e.g. 142.x.x.x from a browser tab) must never become scan targets.
        if not addr.is_private:
            return
        # APIPA is handled as an orphan signal, not a scan target
        if ip.startswith("169.254."):
            return
        # Collapse to the observed /24 — full CIDR correction is a separate patch
        parts = ip.split(".")
        subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        with self._lock:
            if subnet in self._known:
                return
            self._known.add(subnet)
        if self.on_new_subnet:
            self.on_new_subnet(SniffedSubnet(subnet=subnet, first_seen_ip=ip, source=source))

    def _capture_raw(self, iface_ip: str):
        """Raw IP socket capture — sees every packet on the interface."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            if iface_ip:
                try:
                    s.bind((iface_ip, 0))
                except Exception:
                    pass
            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            # Windows: enable promiscuous capture
            try:
                s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            except (AttributeError, OSError):
                s.close()
                return   # Not Windows or no admin — ARP poller covers us
            s.settimeout(1.0)
            try:
                while self._running:
                    try:
                        data = s.recv(65535)
                    except socket.timeout:
                        continue
                    except OSError:
                        break
                    if len(data) < 20:
                        continue
                    src = socket.inet_ntoa(data[12:16])
                    dst = socket.inet_ntoa(data[16:20])
                    self._report(src, "packet")
                    self._report(dst, "packet")
            finally:
                try:
                    s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                except Exception:
                    pass
                s.close()
        except PermissionError:
            pass   # No admin — ARP poller handles discovery
        except Exception:
            pass

    def _poll_arp(self):
        """Poll ARP table every 5 s — works without admin privileges."""
        while self._running:
            try:
                for entry in get_arp_table():
                    self._report(entry["ip"], "arp")
            except Exception:
                pass
            for _ in range(50):   # sleep 5 s in 0.1 s chunks so stop() is responsive
                if not self._running:
                    break
                time.sleep(0.1)
