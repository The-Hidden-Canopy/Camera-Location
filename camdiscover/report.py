"""Report generation — CSV, JSON, HTML, and text summary exports"""

from __future__ import annotations

import csv
import json
import os
import html
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
        "Device Class", "Classification Rationale", "Reset Risk",
        "Notes",
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
            d.device_class,
            d.classification_rationale,
            d.effective_reset_risk,
            d.notes,
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


def _evidence_table(dev: DiscoveredDevice) -> str:
    """Build an HTML evidence-ledger table for a single device."""
    if not dev.evidence:
        return '<p class="muted">No evidence recorded.</p>'
    rows = []
    for ev in dev.evidence:
        rows.append(
            f'<tr>'
            f'<td>{html.escape(ev.kind)}</td>'
            f'<td>{html.escape(ev.detail[:120])}</td>'
            f'<td>{html.escape(ev.source)}</td>'
            f'<td>{ev.weight}</td>'
            f'<td>{ev.timestamp.strftime("%Y-%m-%d %H:%M")}</td>'
            f'</tr>'
        )
    return (
        '<table class="evidence">'
        '<thead><tr><th>Kind</th><th>Detail</th><th>Source</th><th>Weight</th><th>Time</th></tr></thead>'
        '<tbody>' + "\n".join(rows) + '</tbody></table>'
    )


def _dpi_table(dev: DiscoveredDevice) -> str:
    """Build an HTML DPI stage table for a single device."""
    from .models import DPI_STAGES, DPI_STAGE_LABELS
    rows = []
    for stage in DPI_STAGES:
        result = dev.dpi_stages.get(stage)
        if result:
            status_class = {"pass": "ok", "fail": "fail", "unchecked": "warn", "na": "muted"}.get(result.status, "muted")
            rows.append(
                f'<tr>'
                f'<td>{html.escape(DPI_STAGE_LABELS.get(stage, stage))}</td>'
                f'<td class="{status_class}">{html.escape(result.status.upper())}</td>'
                f'<td>{html.escape(result.detail[:120])}</td>'
                f'</tr>'
            )
    if not rows:
        return '<p class="muted">No DPI stages checked.</p>'
    return (
        '<table class="dpi">'
        '<thead><tr><th>Stage</th><th>Status</th><th>Detail</th></tr></thead>'
        '<tbody>' + "\n".join(rows) + '</tbody></table>'
    )


def export_to_html(devices: List[DiscoveredDevice], filename: str) -> str:
    """Export a comprehensive HTML asset report with evidence ledger, DPI stages,
    classification rationale, and operator notes."""
    now = datetime.now().isoformat()
    total = len(devices)
    cameras = [d for d in devices if d.device_class == "camera"]
    nvrs = [d for d in devices if d.device_class == "nvr"]
    infra = [d for d in devices if d.device_class in ("bridge", "router", "switch")]
    unknown = [d for d in devices if d.device_class == "unknown"]

    def _device_card(dev: DiscoveredDevice) -> str:
        risk = dev.effective_reset_risk
        risk_class = {"low": "ok", "moderate": "warn", "high": "fail", "critical": "fail"}.get(risk, "muted")
        return (
            f'<section class="device-card" id="{html.escape(dev.device_id)}">'
            f'<h3>{html.escape(dev.ip)} <span class="tag {html.escape(dev.device_class)}">'
            f'{html.escape(dev.device_class.upper())}</span></h3>'
            f'<div class="meta">'
            f'<span><strong>MAC:</strong> {html.escape(dev.mac or "—")}</span>'
            f'<span><strong>Vendor:</strong> {html.escape(dev.vendor)}</span>'
            f'<span><strong>Model:</strong> {html.escape(dev.model or "—")}</span>'
            f'<span><strong>Hostname:</strong> {html.escape(dev.hostname or "—")}</span>'
            f'<span><strong>Subnet:</strong> {html.escape(dev.subnet)}</span>'
            f'<span><strong>Confidence:</strong> {dev.camera_confidence}%</span>'
            f'<span><strong>Reset Risk:</strong> <span class="{risk_class}">{html.escape(risk.upper())}</span></span>'
            f'</div>'
            f'<p class="rationale"><strong>Why:</strong> {html.escape(dev.classification_rationale or "No rationale recorded.")}</p>'
            f'<p class="notes"><strong>Notes:</strong> {html.escape(dev.notes or "—")}</p>'
            f'<details><summary>Evidence Ledger ({len(dev.evidence)} items)</summary>'
            f'{_evidence_table(dev)}</details>'
            f'<details><summary>DPI Stages</summary>'
            f'{_dpi_table(dev)}</details>'
            f'<details><summary>Raw URLs / Ports</summary>'
            f'<ul>'
            f'<li>Web: {html.escape(dev.web_url or "—")}</li>'
            f'<li>RTSP: {html.escape(dev.rtsp_url or "—")}</li>'
            f'<li>ONVIF: {html.escape(dev.onvif_url or "—")}</li>'
            f'<li>Open Ports: {", ".join(str(p) for p in dev.open_ports) or "—"}</li>'
            f'<li>Protocols: {", ".join(dev.protocols) or "—"}</li>'
            f'<li>Discovery Methods: {", ".join(dev.discovery_methods) or "—"}</li>'
            f'</ul></details>'
            f'</section>'
        )

    cards = "\n".join(_device_card(d) for d in devices)

    html_doc = f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Camera Discovery Octopus — Asset Report</title>
<style>
  body {{ font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; margin: 2rem; background:#f7f8fa; color:#222; }}
  h1 {{ margin-bottom: .25rem; }}
  .meta-bar {{ display:flex; gap:1.5rem; flex-wrap:wrap; margin:1rem 0 1.5rem; }}
  .meta-bar .stat {{ background:#fff; border:1px solid #e2e4e9; padding:.5rem .75rem; border-radius:.4rem; }}
  .device-card {{ background:#fff; border:1px solid #e2e4e9; border-radius:.5rem; padding:1rem; margin-bottom:1rem; }}
  .device-card h3 {{ margin:0 0 .5rem; display:flex; gap:.5rem; align-items:center; }}
  .tag {{ font-size:.75rem; padding:.15rem .4rem; border-radius:.25rem; background:#e2e4e9; }}
  .tag.CAMERA {{ background:#d1f2d1; }}
  .tag.NVR {{ background:#d1e7f2; }}
  .tag.ROUTER, .tag.BRIDGE, .tag.SWITCH {{ background:#f2d1d1; }}
  .meta {{ display:flex; gap:1rem; flex-wrap:wrap; font-size:.9rem; color:#555; margin-bottom:.5rem; }}
  .rationale, .notes {{ font-size:.9rem; margin:.25rem 0; }}
  details {{ margin-top:.5rem; }}
  summary {{ cursor:pointer; font-weight:600; }}
  table {{ width:100%; border-collapse:collapse; font-size:.85rem; margin-top:.4rem; }}
  th, td {{ text-align:left; padding:.35rem .5rem; border-bottom:1px solid #e2e4e9; }}
  th {{ background:#f7f8fa; }}
  .ok {{ color:#1a7f37; }}
  .warn {{ color:#9a6700; }}
  .fail {{ color:#cf222e; }}
  .muted {{ color:#666; }}
</style>
</head>
<body>
<h1>Camera Discovery Octopus — Asset Report</h1>
<p class="muted">Generated: {html.escape(now)}</p>
<div class="meta-bar">
  <div class="stat"><strong>Total</strong> {total}</div>
  <div class="stat"><strong>Cameras</strong> {len(cameras)}</div>
  <div class="stat"><strong>NVRs</strong> {len(nvrs)}</div>
  <div class="stat"><strong>Infrastructure</strong> {len(infra)}</div>
  <div class="stat"><strong>Unknown</strong> {len(unknown)}</div>
</div>
{cards}
</body>
</html>'''

    with open(filename, "w", encoding="utf-8") as f:
        f.write(html_doc)
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
