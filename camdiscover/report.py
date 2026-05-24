"""Report generation — CSV, JSON, and text summary exports"""

from __future__ import annotations

import csv
import json
import os
from datetime import datetime
from typing import List

from .models import DiscoveredDevice


def export_to_csv(devices: List[DiscoveredDevice], filename: str) -> str:
    """Export discovered devices to CSV file."""
    headers = [
        "IP Address", "MAC Address", "Vendor", "Model", "Hostname",
        "Open Ports", "Protocols", "ONVIF Status", "RTSP Status",
        "Web URL", "RTSP URL", "ONVIF URL", "Subnet",
        "Confidence", "Discovery Methods", "Last Seen",
    ]

    rows = []
    for d in devices:
        rows.append([
            d.ip,
            d.mac or "",
            d.vendor,
            d.model,
            d.hostname,
            ";".join(str(p) for p in d.open_ports),
            ";".join(d.protocols),
            d.onvif_status,
            d.rtsp_status,
            d.web_url,
            d.rtsp_url,
            d.onvif_url,
            d.subnet,
            f"{d.camera_confidence}%",   # Gap 11: evidence-based score
            ";".join(d.discovery_methods),
            d.last_seen.isoformat(),
        ])

    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        writer.writerows(rows)

    return filename


def export_to_json(devices: List[DiscoveredDevice], filename: str) -> str:
    """Export discovered devices to JSON file."""
    data = [d.to_dict() for d in devices]

    with open(filename, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    return filename


def generate_summary(devices: List[DiscoveredDevice]) -> str:
    """Generate a text summary report."""
    lines = []
    lines.append("=" * 66)
    lines.append("       CAMERA DISCOVERY OCTOPUS  —  REPORT")
    lines.append("=" * 66)
    lines.append("")
    lines.append(f"Generated: {datetime.now().isoformat()}")
    lines.append(f"Total devices found: {len(devices)}")
    lines.append("")

    # By vendor
    by_vendor: dict[str, int] = {}
    for d in devices:
        by_vendor[d.vendor] = by_vendor.get(d.vendor, 0) + 1

    lines.append("-- By Vendor --")
    for vendor, count in sorted(by_vendor.items(), key=lambda x: -x[1]):
        lines.append(f"  {vendor}: {count}")
    lines.append("")

    # Protocols
    with_onvif = sum(1 for d in devices if d.onvif_status == "found")
    with_rtsp = sum(1 for d in devices if d.rtsp_status == "found")
    with_web = sum(1 for d in devices if d.web_url)
    lines.append("-- Protocols --")
    lines.append(f"  ONVIF capable: {with_onvif}")
    lines.append(f"  RTSP capable: {with_rtsp}")
    lines.append(f"  Web UI found: {with_web}")
    lines.append("")

    # Device details
    lines.append("-- Device Details --")
    for d in devices:
        lines.append(f"  {d.ip:<16} {d.mac or 'no MAC':<18} {d.vendor:<20} {d.model or 'unknown'}")
        if d.web_url:
            lines.append(f"    Web:   {d.web_url}")
        if d.rtsp_url:
            lines.append(f"    RTSP:  {d.rtsp_url}")
        if d.onvif_url:
            lines.append(f"    ONVIF: {d.onvif_url}")
        if d.open_ports:
            lines.append(f"    Ports: {', '.join(str(p) for p in d.open_ports)}")
        lines.append(f"    Confidence: {d.camera_confidence}% | Methods: {', '.join(d.discovery_methods)}")
        lines.append("")

    return "\n".join(lines)
