#!/usr/bin/env python3
"""
Camera Discovery Octopus — Vendor-agnostic IP camera discovery tool
Passive sniffer + DHCP catcher + ONVIF finder + RTSP/web scanner + MAC/vendor identifier + subnet mapper
"""

__version__ = "1.0.0"

# Primary TCP service ports used for discovery and coarse classification.
# We still bias toward camera/NVR protocols, but include a small set of
# common infrastructure and endpoint services so the app can classify more
# than just cameras.
CAMERA_PORTS = {
    22:      "SSH management",
    23:      "Telnet management",
    53:      "DNS service",
    80:      "HTTP web UI",
    443:     "HTTPS web UI",
    554:     "RTSP streaming",
    631:     "IPP printing",
    8000:    "Hikvision SDK/service",
    8080:    "Alternate web UI",
    8443:    "Alternate HTTPS",
    8554:    "Alternate RTSP",
    8899:    "ONVIF device service",
    9100:    "JetDirect printing",
    3389:    "RDP",
    445:     "SMB file sharing",
    37777:   "Dahua/Amcrest service",
    37778:   "Dahua alternate",
    3702:    "ONVIF WS-Discovery (UDP)",
    1900:    "SSDP/UPnP (UDP)",
    5353:    "mDNS (UDP)",
}

ALL_CAMERA_PORTS = sorted(CAMERA_PORTS.keys())

CAMERA_SUBNETS = [
    "192.168.1.0/24",
    "192.168.0.0/24",
    "192.168.2.0/24",
    "192.168.254.0/24",
    "10.0.0.0/24",
    "10.1.1.0/24",
    "10.0.1.0/24",
    "172.16.0.0/24",
    "172.28.0.0/24",
]

DISCOVERY_MODES = {
    "listen":      "Listen-only — passive sniffing, no scanning",
    "dhcp-trap":   "DHCP trap — camera gets IP from your box",
    "sweep":       "Active sweep — scan likely subnets",
    "fingerprint": "Vendor fingerprint — MAC OUI + ports + banners + ONVIF",
    "dpi":         "DPI validation — protocol-stage validation per device",
    "report":      "Report mode — export CSV/JSON with all findings",
}

ONVIF_PROBE_TEMPLATE = """<?xml version="1.0" encoding="UTF-8"?>
<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope"
            xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing"
            xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery"
            xmlns:dn="http://www.onvif.org/ver10/network/wsdl">
  <e:Header>
    <w:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action>
    <w:MessageID>urn:uuid:{message_id}</w:MessageID>
    <w:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>
  </e:Header>
  <e:Body>
    <d:Probe>
      <d:Types>dn:NetworkVideoTransmitter</d:Types>
    </d:Probe>
  </e:Body>
</e:Envelope>"""

SSDP_SEARCH_TEMPLATE = "\r\n".join([
    "M-SEARCH * HTTP/1.1",
    "HOST: 239.255.255.250:1900",
    'MAN: "ssdp:discover"',
    "MX: 3",
    "ST: ssdp:all",
    "",
    "",
])
