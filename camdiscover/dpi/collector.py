"""
DPI Collector — passive evidence engine.

Binds to multicast/broadcast groups and watches for camera self-announcement
traffic. Each captured signal is emitted as an (ip, kind, detail, source, weight, raw)
callback so the orchestrator can merge it into device records in real-time.

Protocol coverage:
  UDP 3702   ONVIF WS-Discovery (multicast 239.255.255.250)
  UDP 37020  Hikvision SADP-style discovery (broadcast)
  UDP 1900   SSDP / UPnP (multicast 239.255.255.250)
  UDP 5353   mDNS (multicast 224.0.0.251)
  RAW IGMP   IGMP Membership Reports (Gap 4 — raw socket, admin-only, silent skip)
  UDP RTP    Camera RTP multicast streams (Gap 5 — joins known camera groups)

All listeners are daemon threads and tolerate port-already-in-use errors silently
(the existing PassiveListener may already be holding some of these ports).
"""

from __future__ import annotations

import re
import socket
import struct
import threading
import time
from datetime import datetime
from typing import Callable, List, Optional

from .evidence import (
    EVIDENCE_WEIGHTS,
    CAMERA_VENDOR_KEYWORDS,
    NON_CAMERA_WSD_KEYWORDS,
)


class DPICollector:
    """
    Passive evidence collector.  Start it at the beginning of any scan mode;
    it runs in the background emitting Evidence signals as cameras announce
    themselves on the wire.
    """

    def __init__(self):
        self._running = False
        self._threads: List[threading.Thread] = []
        self._sockets: List[socket.socket] = []
        self._lock = threading.Lock()

        # Callback signature:
        #   on_evidence(ip: str, kind: str, detail: str, source: str,
        #               weight: int, raw: str) -> None
        self.on_evidence: Optional[Callable] = None

    # ─── Lifecycle ────────────────────────────────────────────────────────

    def start(self, interface_ip: str = ""):
        if self._running:
            return
        self._running = True
        for fn in (
            self._listen_onvif_wsdiscovery,
            self._listen_sadp,
            self._listen_ssdp,
            self._listen_mdns,
            self._listen_dhcp,
            self._listen_igmp,          # Gap 4: IGMP membership reports (admin-only raw socket)
            self._listen_rtp_multicast, # Gap 5: RTP streams on known camera multicast groups
            self._listen_lldp,          # Gap 6: LLDP neighbor announcements (admin-only raw socket)
        ):
            t = threading.Thread(target=fn, args=(interface_ip,), daemon=True,
                                 name=f"dpi-{fn.__name__}")
            t.start()
            self._threads.append(t)

    def stop(self):
        self._running = False
        with self._lock:
            for s in self._sockets:
                try:
                    s.close()
                except Exception:
                    pass
            self._sockets.clear()

    # ─── Emit helper ──────────────────────────────────────────────────────

    def _emit(self, ip: str, kind: str, detail: str, source: str, raw: str = ""):
        if not ip or not self.on_evidence:
            return
        weight = EVIDENCE_WEIGHTS.get(kind, 0)
        try:
            self.on_evidence(ip, kind, detail, source, weight, raw)
        except Exception:
            pass

    # ─── Socket helpers ───────────────────────────────────────────────────

    @staticmethod
    def _udp_socket() -> socket.socket:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)  # type: ignore
        except AttributeError:
            pass   # not available on Windows
        return s

    @staticmethod
    def _join_multicast(sock: socket.socket, group: str, iface_ip: str):
        iface_bytes = socket.inet_aton(iface_ip) if iface_ip else b'\x00\x00\x00\x00'
        mreq = struct.pack("4s4s", socket.inet_aton(group), iface_bytes)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

    def _track(self, s: socket.socket):
        with self._lock:
            self._sockets.append(s)

    # ─── ONVIF WS-Discovery — UDP 3702 ────────────────────────────────────

    def _listen_onvif_wsdiscovery(self, iface_ip: str):
        """
        Listen on multicast 239.255.255.250:3702 for ONVIF Probe/Hello/ProbeMatch.
        Cameras announce themselves here on start-up and in response to probes.
        """
        MCAST, PORT = "239.255.255.250", 3702
        try:
            s = self._udp_socket()
            try:
                s.bind(("", PORT))
            except OSError:
                s.close()
                return   # port in use — PassiveListener already there
            self._join_multicast(s, MCAST, iface_ip)
            s.settimeout(1.0)
            self._track(s)

            while self._running:
                try:
                    data, addr = s.recvfrom(65535)
                    src_ip = addr[0]
                    if src_ip.startswith(("239.", "224.")):
                        continue
                    self._parse_wsdiscovery(src_ip, data)
                except socket.timeout:
                    continue
                except OSError:
                    break
        except Exception:
            pass

    def _parse_wsdiscovery(self, ip: str, data: bytes):
        try:
            text = data.decode("utf-8", errors="replace")
        except Exception:
            return

        tl = text.lower()

        is_match = "probematches" in tl or "probematch" in tl
        is_hello = "hello" in tl
        has_nvt  = "networkvideotransmitter" in tl or "networkvideodisplay" in tl
        has_svc  = "device_service" in tl or "/onvif/" in tl
        is_onvif = "onvif" in tl

        if not (is_match or is_hello or is_onvif):
            return

        # Extract XAddr (device service endpoint URL)
        xaddr = ""
        m = re.search(r'<[^>:]*XAddr[^>]*>\s*([^\s<]+)\s*<', text)
        if m:
            xaddr = m.group(1).strip()

        # Subnet-mismatch hint: XAddr IP differs from sender
        if xaddr:
            reported = re.search(r'//([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)', xaddr)
            if reported and reported.group(1) != ip:
                self._emit(ip, "subnet_mismatch_visible",
                           f"XAddr reports {reported.group(1)} but packet came from {ip}",
                           "passive_wsdiscovery", xaddr)

        # High-confidence: NVT type in ProbeMatch
        if has_nvt and (is_match or is_hello):
            detail = "ONVIF WS-Discovery ProbeMatch (NetworkVideoTransmitter)"
            if xaddr:
                detail += f" — {xaddr}"
            self._emit(ip, "onvif_probe_match_nvt", detail, "passive_wsdiscovery",
                       text[:500])
        elif is_onvif and (is_match or is_hello):
            self._emit(ip, "onvif_probe_match_generic",
                       f"ONVIF WS-Discovery {'ProbeMatch' if is_match else 'Hello'}",
                       "passive_wsdiscovery", text[:500])

        if has_svc and xaddr:
            self._emit(ip, "onvif_device_service_url",
                       f"ONVIF device_service: {xaddr}",
                       "passive_wsdiscovery", xaddr)

        # Negative: clearly non-camera WSD device
        if any(kw in tl for kw in NON_CAMERA_WSD_KEYWORDS) and not has_nvt:
            self._emit(ip, "wsd_non_camera",
                       "WS-Discovery response without NVT — likely not a camera",
                       "passive_wsdiscovery")

    # ─── Hikvision SADP — UDP 37020 ───────────────────────────────────────

    def _listen_sadp(self, iface_ip: str):
        """
        Listen on broadcast UDP 37020 for Hikvision SADP responses.
        Also sends a probe so cameras respond immediately.
        """
        PORT = 37020
        try:
            s = self._udp_socket()
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            try:
                s.bind(("", PORT))
            except OSError:
                s.close()
                return
            s.settimeout(1.0)
            self._track(s)

            # Send SADP inquiry probe
            try:
                # Minimal SADP inquiry packet (16 zero bytes triggers response)
                s.sendto(b'\x20' + b'\x00' * 15, ("255.255.255.255", PORT))
            except Exception:
                pass

            while self._running:
                try:
                    data, addr = s.recvfrom(65535)
                    src_ip = addr[0]
                    self._parse_sadp(src_ip, data)
                except socket.timeout:
                    continue
                except OSError:
                    break
        except Exception:
            pass

    def _parse_sadp(self, ip: str, data: bytes):
        if len(data) < 8:
            return
        try:
            text = data.decode("utf-8", errors="replace")
        except Exception:
            text = repr(data)

        detail_parts: list[str] = []
        sadp_fields = [
            "DeviceType", "DeviceDescription", "CommandPort", "HttpPort",
            "IPv4Address", "IPv4SubnetMask", "IPv4Gateway", "MAC",
            "DHCP", "DSPVersion", "Activated", "PasswordResetAbility",
        ]
        reported_ip = ""
        for field in sadp_fields:
            m = re.search(rf'<{field}[^>]*>([^<]+)</{field}>', text)
            if m:
                val = m.group(1).strip()
                detail_parts.append(f"{field}={val}")
                if field == "IPv4Address":
                    reported_ip = val

        if not detail_parts:
            # Binary SADP — still count as evidence if it's on port 37020
            detail_parts.append(f"binary SADP response ({len(data)} bytes)")

        detail = "SADP: " + ", ".join(detail_parts[:6])  # first 6 fields

        # Subnet mismatch: camera reports a different IP than we see on wire
        if reported_ip and reported_ip != ip:
            self._emit(ip, "subnet_mismatch_visible",
                       f"SADP IPv4Address={reported_ip} but packet from {ip}",
                       "passive_sadp", text[:300])

        self._emit(ip, "sadp_response", detail, "passive_sadp", text[:500])

    # ─── SSDP / UPnP — UDP 1900 ───────────────────────────────────────────

    def _listen_ssdp(self, iface_ip: str):
        MCAST, PORT = "239.255.255.250", 1900
        try:
            s = self._udp_socket()
            try:
                s.bind(("", PORT))
            except OSError:
                s.close()
                return
            self._join_multicast(s, MCAST, iface_ip)
            s.settimeout(1.0)
            self._track(s)

            while self._running:
                try:
                    data, addr = s.recvfrom(65535)
                    src_ip = addr[0]
                    if src_ip.startswith("239."):
                        continue
                    self._parse_ssdp(src_ip, data)
                except socket.timeout:
                    continue
                except OSError:
                    break
        except Exception:
            pass

    def _parse_ssdp(self, ip: str, data: bytes):
        try:
            text = data.decode("utf-8", errors="replace")
        except Exception:
            return
        tl = text.lower()

        camera_kw = {"camera", "nvr", "dvr", "onvif", "rtsp", "video",
                     "surveillance", "ipcam", "ip cam", "hikvision", "dahua",
                     "axis", "reolink", "uniview"}
        non_camera_kw = {"printer", "renderer", "mediaserver", "mediarenderer",
                         "dial-multiscreen", "basic:1"}

        has_cam = any(k in tl for k in camera_kw)
        has_non = any(k in tl for k in non_camera_kw) and not has_cam

        if has_cam:
            server = re.search(r'server:\s*([^\r\n]+)', tl)
            loc    = re.search(r'location:\s*([^\r\n]+)', tl)
            detail = f"SSDP camera service from {ip}"
            if server:
                detail += f" [{server.group(1).strip()}]"
            if loc:
                detail += f" loc={loc.group(1).strip()}"
            self._emit(ip, "ssdp_camera_service", detail, "passive_ssdp")
        elif has_non:
            self._emit(ip, "wsd_non_camera",
                       f"SSDP non-camera UPnP device from {ip}", "passive_ssdp")

    # ─── mDNS — UDP 5353 ──────────────────────────────────────────────────

    def _listen_mdns(self, iface_ip: str):
        MCAST, PORT = "224.0.0.251", 5353
        try:
            s = self._udp_socket()
            try:
                s.bind(("", PORT))
            except OSError:
                s.close()
                return
            self._join_multicast(s, MCAST, iface_ip)
            s.settimeout(1.0)
            self._track(s)

            while self._running:
                try:
                    data, addr = s.recvfrom(65535)
                    src_ip = addr[0]
                    if src_ip.startswith("224."):
                        continue
                    self._parse_mdns(src_ip, data)
                except socket.timeout:
                    continue
                except OSError:
                    break
        except Exception:
            pass

    def _parse_mdns(self, ip: str, data: bytes):
        # DNS is binary; scan for recognisable ASCII camera strings
        try:
            text = data.decode("utf-8", errors="replace")
        except Exception:
            return
        tl = text.lower()

        camera_svc = {
            "_onvif", "_rtsp", "_nvr", "_dvr", "_camera", "_ipcam",
            "hikvision", "dahua", "axis", "reolink", "_axis-video",
        }
        if any(svc in tl for svc in camera_svc):
            self._emit(ip, "mdns_camera_service",
                       f"mDNS camera service announcement from {ip}",
                       "passive_mdns", text[:300])

    # ─── DHCP snooping — UDP 68 (client port) ────────────────────────────
    #
    # Cameras and NVRs send DHCP DISCOVER / REQUEST on port 68.  Binding
    # to UDP 68 on Windows requires admin rights; if the bind fails we silently
    # skip this listener.  We only emit evidence for hostnames that match
    # camera vendor keywords — not for every DHCP request.
    #
    # DHCP packet structure (simplified):
    #   Byte 28-43: 16-byte client IP (ciaddr); Byte 44-47: your IP (yiaddr)
    #   Options start at byte 236; option 12 = Hostname, option 60 = Vendor class.

    def _listen_dhcp(self, iface_ip: str):
        # DHCP client port 68 is typically owned by the OS DHCP client service
        # on Windows. We try binding to it first; if that fails (it usually does
        # on Windows), we fall back to binding to the DHCP server port 67 with
        # broadcast enabled. On port 67 we can see DHCP requests (DISCOVER/REQUEST)
        # broadcast from clients even though we're not actually a DHCP server.
        for PORT in (68, 67):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                try:
                    s.bind(("", PORT))
                except OSError:
                    s.close()
                    continue  # try next port
                s.settimeout(1.0)
                self._track(s)

                while self._running:
                    try:
                        data, addr = s.recvfrom(1500)
                        self._parse_dhcp(data, addr)
                    except socket.timeout:
                        continue
                    except OSError:
                        break
                return
            except Exception:
                pass

    def _parse_dhcp(self, data: bytes, addr):
        """Parse a DHCP packet for hostname and vendor class strings."""
        if len(data) < 240:
            return
        # Source IP from UDP addr tuple
        src_ip = addr[0]
        # ciaddr (client IP) at offset 12, yiaddr at offset 16
        try:
            ciaddr = ".".join(str(b) for b in data[12:16])
            yiaddr = ".".join(str(b) for b in data[16:20])
        except Exception:
            return

        # The "real" client IP is ciaddr if non-zero, else the UDP source
        client_ip = ciaddr if ciaddr != "0.0.0.0" else (
            yiaddr if yiaddr != "0.0.0.0" else src_ip)
        if not client_ip or client_ip in ("0.0.0.0", "255.255.255.255"):
            return

        # Parse options (start at offset 240 after 4-byte magic cookie)
        hostname = ""
        vendor_class = ""
        try:
            opts = data[240:]
            i = 0
            while i < len(opts) - 1:
                opt = opts[i]
                if opt == 255:   # END
                    break
                if opt == 0:     # PAD
                    i += 1
                    continue
                length = opts[i + 1]
                value = opts[i + 2: i + 2 + length]
                if opt == 12:    # Hostname
                    hostname = value.decode("ascii", errors="replace")
                elif opt == 60:  # Vendor class identifier
                    vendor_class = value.decode("ascii", errors="replace")
                i += 2 + length
        except Exception:
            pass

        # Emit only if it looks camera/NVR related
        cam_kw = {"cam", "ipcam", "nvr", "dvr", "hikv", "dahua", "amcrest",
                  "axis", "reolink", "onvif", "camera", "cctv", "hikvision",
                  "uniview", "hanwha", "wisenet"}
        combined = (hostname + " " + vendor_class).lower()
        is_camera = any(k in combined for k in cam_kw)

        detail = f"DHCP request from {client_ip}"
        if hostname:
            detail += f" hostname={hostname}"
        if vendor_class:
            detail += f" class={vendor_class}"

        if is_camera:
            self._emit(client_ip, "dhcp_hostname_camera", detail,
                       "passive_dhcp", combined[:200])
        else:
            # Still emit a weak dhcp_request signal so the triage engine
            # knows the device is alive and DHCP-seeking (useful for APIPA
            # detection when no IP is assigned yet).
            self._emit(client_ip, "dhcp_request", detail,
                       "passive_dhcp", combined[:200])

    # ─── Gap 4: IGMP Membership Reports — raw socket (admin-only) ────────
    #
    # Cameras and NVRs send IGMP Membership Reports when they JOIN a multicast
    # group to receive an RTP stream.  The report tells us:
    #   Source IP  → the camera/NVR doing the join
    #   Group IP   → the multicast address being joined
    #
    # Raw IPPROTO_IGMP sockets require elevated privileges on Windows.
    # If the bind fails (access denied, privileges missing) we silently skip
    # so the rest of the DPI collector keeps working.
    #
    # The `raw` field of the emitted evidence carries the group IP so the
    # orchestrator can update MulticastGroup.listeners for that group.

    def _listen_igmp(self, iface_ip: str):
        """Raw IGMP socket — captures v1/v2 Membership Reports.
        Silently skipped if not running as administrator."""
        IGMP_PROTO = 2  # socket.IPPROTO_IGMP
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, IGMP_PROTO)
            try:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            except Exception:
                pass
            if iface_ip:
                try:
                    s.bind((iface_ip, 0))
                except OSError:
                    pass  # bind error is non-fatal; we still receive on all IFs
            s.settimeout(1.0)
            self._track(s)

            while self._running:
                try:
                    data, addr = s.recvfrom(65535)
                    src_ip = addr[0]
                    # Skip packets from multicast/broadcast addresses
                    if src_ip.startswith(("224.", "239.", "234.", "255.")):
                        continue
                    self._parse_igmp(src_ip, data)
                except socket.timeout:
                    continue
                except OSError:
                    break
        except Exception:
            pass  # PermissionError on Windows without admin — skip silently

    def _parse_igmp(self, src_ip: str, data: bytes):
        """Parse a raw IP packet containing an IGMP v1/v2 Membership Report.

        On Windows raw sockets deliver the full IP packet including the IP header.
        IP header length = (data[0] & 0x0F) * 4 bytes.

        IGMPv2 Membership Report (type 0x16):
          Byte 0:   type  (0x12 = v1 report, 0x16 = v2 report)
          Byte 1:   max response time
          Bytes 2-3: checksum
          Bytes 4-7: group address (the multicast group being joined)
        """
        try:
            if len(data) < 20:
                return
            ihl = (data[0] & 0x0F) * 4
            if len(data) < ihl + 8:
                return
            igmp = data[ihl:]
            igmp_type = igmp[0]
            # 0x12 = IGMPv1 report, 0x16 = IGMPv2 Membership Report
            if igmp_type not in (0x12, 0x16):
                return
            group = ".".join(str(b) for b in igmp[4:8])
            if not (group.startswith("224.") or group.startswith("239.")
                    or group.startswith("234.")):
                return
            detail = f"IGMP Membership Report: {src_ip} joining {group}"
            # raw = group IP so orchestrator can update MulticastGroup.listeners
            self._emit(src_ip, "igmp_multicast_stream", detail,
                       "passive_igmp", group)
        except Exception:
            pass

    # ─── Gap 5: RTP Multicast Streams — join known camera groups ─────────
    #
    # RTP multicast groups are now discovered dynamically via IGMP membership
    # reports (_listen_igmp).  When a device joins a multicast group we learn
    # its address at runtime; the orchestrator can then call join_rtp_group()
    # to start listening.  No static group list is consulted.

    def _listen_rtp_multicast(self, iface_ip: str):
        """RTP group listener — starts with no groups; groups are added at
        runtime via join_rtp_group() as IGMP membership reports reveal them."""
        self._rtp_sockets: dict = {}   # group -> socket
        self._rtp_iface_ip = iface_ip
        # Thread just keeps running so join_rtp_group() calls have a live context.
        # Actual receive happens in the same thread via a tight poll loop.
        while self._running:
            groups = list(self._rtp_sockets.items())
            for group, s in groups:
                try:
                    data, addr = s.recvfrom(4096)
                    src_ip = addr[0]
                    if src_ip.startswith(("224.", "239.", "234.")):
                        continue
                    if self._is_rtp(data):
                        detail = (f"RTP media flow: {src_ip} → multicast {group} "
                                  f"(PT={data[1] & 0x7F})")
                        self._emit(src_ip, "rtp_flow", detail, "passive_rtp", group)
                except socket.timeout:
                    continue
                except OSError:
                    self._rtp_sockets.pop(group, None)
            time.sleep(0.02)

    def join_rtp_group(self, group: str):
        """Dynamically join a newly-discovered multicast group to capture RTP.

        Called by the orchestrator when an IGMP membership report reveals a
        group we haven't seen before.  Safe to call from any thread.
        """
        rtp_sockets = getattr(self, "_rtp_sockets", None)
        if rtp_sockets is None or group in rtp_sockets:
            return
        iface_ip = getattr(self, "_rtp_iface_ip", "")
        try:
            s = self._udp_socket()
            s.bind(("", 0))
            self._join_multicast(s, group, iface_ip)
            s.settimeout(0.5)
            self._track(s)
            rtp_sockets[group] = s
        except Exception:
            pass

    @staticmethod
    def _is_rtp(data: bytes) -> bool:
        """Quick RTP header sanity check (RFC 3550).

        Returns True if the first 12 bytes look like a valid RTP header:
          - Version field = 2 (bits 7-6 of byte 0)
          - Payload type in a range commonly used for video:
              26   JPEG/MJPEG (static)
              31   H.261
              32   MPEG-1/2 audio+video
              34   H.263
              96-127 dynamic — used for H.264, H.265, HEVC etc.
        """
        if len(data) < 12:
            return False
        version = (data[0] >> 6) & 0x3
        if version != 2:
            return False
        pt = data[1] & 0x7F  # payload type (marker bit stripped)
        return pt in (26, 31, 32, 34) or (96 <= pt <= 127)

    # ─── Gap 6: LLDP — IEEE 802.1AB neighbor discovery ────────────────────
    #
    # Cameras (especially Axis, Cisco-managed, and enterprise deployments)
    # send LLDP frames to multicast 01:80:c2:00:00:0e every ~30s.
    # LLDP TLVs contain: Chassis ID (MAC), Port ID, System Name, System
    # Description, Management Address, and optional vendor-specific OUIs.
    #
    # On Windows this requires a raw socket (admin-only).  If the socket
    # creation fails (not admin, or Windows firewall blocks raw sockets),
    # we silently skip — the rest of the DPI collector keeps working.

    # LLDP EtherType
    LLDP_ETHERTYPE = 0x88cc

    def _listen_lldp(self, iface_ip: str):
        """Raw socket listener for LLDP frames (admin-only, silent skip)."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if iface_ip:
                try:
                    s.bind((iface_ip, 0))
                except OSError:
                    pass
            # Enable promiscuous mode to catch LLDP multicast frames
            try:
                s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            except Exception:
                pass
            s.settimeout(1.0)
            self._track(s)

            while self._running:
                try:
                    data, addr = s.recvfrom(65535)
                    if len(data) < 14:
                        continue
                    # Check for LLDP EtherType in the Ethernet header
                    # On Windows raw sockets, the IP header is included;
                    # we need to scan for the LLDP pattern in the payload.
                    self._parse_lldp_scan(data, addr[0])
                except socket.timeout:
                    continue
                except OSError:
                    break
        except Exception:
            pass  # PermissionError on Windows without admin — skip silently

    def _parse_lldp_scan(self, data: bytes, src_ip: str):
        """Scan raw packet data for LLDP signatures.

        LLDP frames start with destination MAC 01:80:c2:00:00:0e and
        EtherType 0x88cc.  On Windows raw sockets we get IP packets,
        not Ethernet frames, so we scan for LLDP TLV patterns instead.
        """
        # Look for LLDP EtherType signature in the data
        lldp_marker = b'\x88\xcc'
        offset = data.find(lldp_marker)
        if offset < 0:
            return

        # After the EtherType, LLDP TLVs begin.
        # Minimum: Chassis ID TLV (7 bytes) + Port ID TLV (5 bytes) + TTL (2 bytes)
        tlv_start = offset + 2
        if len(data) < tlv_start + 14:
            return

        tlv_data = data[tlv_start:]
        chassis_id = ""
        system_name = ""
        system_desc = ""
        mgmt_ip = ""

        pos = 0
        while pos + 4 <= len(tlv_data):
            # TLV header: 7-bit type + 9-bit length
            header = (tlv_data[pos] << 8) | tlv_data[pos + 1]
            tlv_type = (header >> 9) & 0x7F
            tlv_len = header & 0x1FF

            if pos + 2 + tlv_len > len(tlv_data):
                break

            tlv_value = tlv_data[pos + 2: pos + 2 + tlv_len]

            # Type 0 = End of LLDPDU
            if tlv_type == 0:
                break
            # Type 1 = Chassis ID
            if tlv_type == 1 and tlv_len >= 2:
                subtype = tlv_value[0]
                if subtype == 4 and tlv_len >= 7:  # MAC address
                    chassis_id = ":".join(f"{b:02x}" for b in tlv_value[1:7])
                elif subtype == 1 and tlv_len >= 2:  # Chassis component
                    try:
                        chassis_id = tlv_value[1:].decode("ascii", errors="replace").strip()
                    except Exception:
                        pass
            # Type 5 = System Name
            elif tlv_type == 5:
                try:
                    system_name = tlv_value.decode("utf-8", errors="replace").strip()
                except Exception:
                    pass
            # Type 6 = System Description
            elif tlv_type == 6:
                try:
                    system_desc = tlv_value.decode("utf-8", errors="replace").strip()[:200]
                except Exception:
                    pass
            # Type 8 = Management Address
            elif tlv_type == 8 and tlv_len >= 3:
                addr_len = tlv_value[0]
                addr_subtype = tlv_value[1]
                if addr_subtype == 1 and addr_len >= 5:  # IPv4
                    try:
                        mgmt_ip = ".".join(str(b) for b in tlv_value[2:6])
                    except Exception:
                        pass

            pos += 2 + tlv_len

        # Only emit if we found at least a chassis ID or system name
        if not chassis_id and not system_name:
            return

        detail_parts = ["LLDP neighbor"]
        if chassis_id:
            detail_parts.append(f"chassis={chassis_id}")
        if system_name:
            detail_parts.append(f"name={system_name}")
        if system_desc:
            detail_parts.append(f"desc={system_desc[:80]}")
        if mgmt_ip:
            detail_parts.append(f"mgmt={mgmt_ip}")

        # Use management IP if available, else source IP
        device_ip = mgmt_ip if mgmt_ip else src_ip

        self._emit(device_ip, "lldp_neighbor", " | ".join(detail_parts),
                   "passive_lldp", f"chassis={chassis_id} name={system_name}")
