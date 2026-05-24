#!/usr/bin/env python3
"""
Camera Discovery Octopus — CLI entry point

Usage:
    camera-discover scan                          # Listen-only mode (default)
    camera-discover scan --mode sweep             # Active subnet scan
    camera-discover scan --mode fingerprint       # Full vendor fingerprint
    camera-discover scan --mode dpi               # Full DPI protocol-stage validation
    camera-discover scan --mode dhcp-trap         # DHCP trap mode
    camera-discover scan --no-dashboard           # CLI only (no TUI)
    camera-discover interfaces                    # List network interfaces
    camera-discover ports                         # Show camera port reference
    camera-discover subnets                       # List configured subnet zones
    camera-discover subnets --add 192.168.88.0/24 # Add a subnet zone
    camera-discover dpi <ip>                      # Run DPI validation on a device
    camera-discover capture-pos                   # Show current capture position
"""

from __future__ import annotations

import argparse
import sys
import time
from datetime import datetime
from typing import List

from . import __version__, CAMERA_PORTS, DISCOVERY_MODES
from .models import DiscoveredDevice, SubnetZone, CapturePosition, DPI_STAGES, DPI_STAGE_LABELS
from .orchestrator import DiscoveryOrchestrator
from .network import NetworkInterface, get_interfaces, get_routes
from .report import export_to_csv, export_to_json, generate_summary


def main():
    parser = argparse.ArgumentParser(
        prog="camera-discover",
        description="Camera Discovery Octopus — vendor-agnostic IP camera discovery tool",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # scan command
    scan_parser = subparsers.add_parser("scan", help="Run camera discovery scan")
    scan_parser.add_argument(
        "-m", "--mode",
        choices=list(DISCOVERY_MODES.keys()),
        default="listen",
        help="Discovery mode (default: listen)",
    )
    scan_parser.add_argument("-i", "--interface", help="Network interface name to use")
    scan_parser.add_argument("-s", "--subnet", help="Custom subnet(s), comma-separated")
    scan_parser.add_argument("-o", "--output", help="Output file (.csv or .json)")
    scan_parser.add_argument(
        "--no-dashboard",
        action="store_true",
        help="Run without TUI dashboard (CLI mode only)",
    )

    # interfaces command
    subparsers.add_parser("interfaces", help="List available network interfaces")

    # ports command
    subparsers.add_parser("ports", help="Show camera port reference")

    # web command
    web_parser = subparsers.add_parser("web", help="Launch web dashboard UI")
    web_parser.add_argument("--host", default="0.0.0.0", help="Bind host (default: 0.0.0.0)")
    web_parser.add_argument("--port", type=int, default=5000, help="Bind port (default: 5000)")
    web_parser.add_argument("--no-browser", action="store_true", help="Don't auto-open browser (used by Electron)")

    # subnets command
    subnet_parser = subparsers.add_parser("subnets", help="Manage subnet zones")
    subnet_parser.add_argument("--add", metavar="CIDR", help="Add a subnet zone (e.g. 192.168.88.0/24)")
    subnet_parser.add_argument("--remove", metavar="CIDR", help="Remove a subnet zone")
    subnet_parser.add_argument("--label", help="Label for the subnet zone")
    subnet_parser.add_argument("--gateway", help="Gateway for the subnet zone")
    subnet_parser.add_argument("--method", choices=["auto", "route", "secondary_ip", "manual"], default="auto", help="Reachability method")
    subnet_parser.add_argument("--probe", metavar="CIDR", help="Probe a subnet for connectivity")
    subnet_parser.add_argument("--routes", action="store_true", help="Show current routing table")

    # dpi command
    dpi_parser = subparsers.add_parser("dpi", help="Run DPI protocol-stage validation on a device")
    dpi_parser.add_argument("ip", nargs="?", help="IP address of the device to validate")
    dpi_parser.add_argument("--stages", action="store_true", help="List DPI stage definitions")

    # capture-pos command
    cp_parser = subparsers.add_parser("capture-pos", help="Show or set capture position")
    cp_parser.add_argument("--set", dest="set_position", choices=["wifi", "ethernet_same", "span_port", "inline_tap", "nvr_capture"], help="Set capture position")

    args = parser.parse_args()

    if args.command == "scan":
        run_scan(args)
    elif args.command == "interfaces":
        show_interfaces()
    elif args.command == "ports":
        show_ports()
    elif args.command == "web":
        run_web(args)
    elif args.command == "subnets":
        run_subnets(args)
    elif args.command == "dpi":
        run_dpi(args)
    elif args.command == "capture-pos":
        run_capture_pos(args)
    else:
        show_help()


def run_scan(args):
    """Execute a camera discovery scan."""
    mode = args.mode

    orchestrator = DiscoveryOrchestrator()
    interfaces = orchestrator.select_interface(args.interface)

    if not interfaces:
        print_error("No usable network interfaces found. Check your network connection.")
        sys.exit(1)

    # Select interface
    if args.interface:
        match = next((i for i in interfaces if i.name == args.interface), None)
        if match:
            orchestrator.set_interface(match)
        else:
            print_error(f'Interface "{args.interface}" not found.')
            print("Available interfaces:")
            for i in interfaces:
                print(f"  {i.name} ({i.ip}) — {i.iface_type}")
            sys.exit(1)
    else:
        best = next((i for i in interfaces if i.iface_type == "ethernet"), interfaces[0])
        orchestrator.set_interface(best)
        print_info(f"Auto-selected interface: {best.name} ({best.ip})")

    subnets = args.subnet.split(",") if args.subnet else None

    if not args.no_dashboard:
        # Try TUI dashboard
        try:
            from .dashboard import Dashboard
            dashboard = Dashboard(orchestrator)
            selected_iface = next(
                (i for i in interfaces if i.name == (args.interface or interfaces[0].name)),
                interfaces[0]
            )
            dashboard.set_interface(selected_iface)
            dashboard.run(mode)
            return
        except Exception as e:
            print_info(f"Dashboard unavailable ({e}), falling back to CLI mode.")

    # CLI mode
    run_cli_mode(orchestrator, mode, subnets, args.output)


def run_cli_mode(
    orchestrator: DiscoveryOrchestrator,
    mode: str,
    subnets: List[str] = None,
    output_file: str = None,
):
    """Run discovery in CLI mode (no TUI)."""
    print()
    print_header(f"  Camera Discovery Octopus — {DISCOVERY_MODES.get(mode, mode)}")
    print()

    # Show capture position
    cp = orchestrator.capture_position
    cp_color = "\033[32m" if cp.can_see_unicast and cp.can_see_rtsp else "\033[33m"
    print(f"  Capture: {cp_color}{cp.position}\033[0m  "
          f"unicast={'yes' if cp.can_see_unicast else 'no'}  "
          f"RTSP={'yes' if cp.can_see_rtsp else 'no'}")

    def on_progress(p):
        print(f"\r  [{p.phase}] {p.message}          ", end="", flush=True)

    def on_device(device: DiscoveredDevice):
        print()
        print_success(f"  Found: {device.ip} — {device.vendor} {f'({device.mac})' if device.mac else ''}")

    orchestrator.on_progress = on_progress
    orchestrator.on_device_found = on_device

    try:
        devices = orchestrator.run(mode, subnets)

        # Clear progress line
        print("\r" + " " * 80 + "\r", end="")

        print_header(f"\n  ── Results: {len(devices)} device(s) found ──\n")

        if not devices:
            print_warning("  No cameras discovered. Try:")
            print("    • Use --mode sweep for active subnet scanning")
            print("    • Check that cameras are powered and connected")
            print("    • Try a different network interface with --interface")
            print()
            return

        # Print device table
        for d in devices:
            score_str = color_confidence(d.confidence)
            dpi_str = f" DPI:{d.dpi_score}%" if d.dpi_stages else ""
            print(f"  {d.ip:<16} {d.mac or '---':<18} {d.vendor:<20} {score_str}{dpi_str}")

            if d.model:
                print(f"  {'':16} Model: {d.model}")
            if d.open_ports:
                print(f"  {'':16} Ports: {', '.join(str(p) for p in d.open_ports)}")
            if d.web_url:
                print_info(f"  {'':16} Web:   {d.web_url}")
            if d.rtsp_url:
                print_info(f"  {'':16} RTSP:  {d.rtsp_url}")
            if d.onvif_url:
                print_info(f"  {'':16} ONVIF: {d.onvif_url}")
            if d.subnet_zone:
                print_info(f"  {'':16} Zone:  {d.subnet_zone}")
            # DPI stages summary
            if d.dpi_stages:
                stage_parts = []
                for stage in DPI_STAGES:
                    r = d.dpi_stages.get(stage)
                    if r and r.status != "na":
                        icon = "+" if r.status == "pass" else ("-" if r.status == "fail" else "?")
                        stage_parts.append(f"{icon}{DPI_STAGE_LABELS.get(stage, stage)}")
                if stage_parts:
                    print(f"  {'':16} DPI:   {' '.join(stage_parts)}")
            print()

        # Export
        if output_file:
            if output_file.endswith(".json"):
                export_to_json(devices, output_file)
            else:
                export_to_csv(devices, output_file)
            print_success(f"  Exported to: {output_file}")
        else:
            timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            csv_file = f"camera-discovery-{timestamp}.csv"
            export_to_csv(devices, csv_file)
            print_success(f"  Auto-exported to: {csv_file}")

        # Summary
        print(generate_summary(devices))

    except KeyboardInterrupt:
        orchestrator.stop()
        print_warning("\n  Scan interrupted by user.")
    except Exception as e:
        print_error(f"\n  Error: {e}")
        sys.exit(1)


def show_interfaces():
    """List available network interfaces."""
    from .network import get_interfaces

    interfaces = get_interfaces()
    type_icons = {
        "ethernet": "  ",
        "wi-fi": "  ",
        "virtual": "  ",
        "loopback": "  ",
        "unknown": "  ",
    }

    print_header("\n  Network Interfaces:\n")
    for i in interfaces:
        icon = type_icons.get(i.iface_type, "  ")
        print(f"  {icon} {i.name}")
        print(f"     IP: {i.ip}  MAC: {i.mac or 'N/A'}  Type: {i.iface_type}")
        print(f"     Subnet: {i.subnet}  Gateway: {i.gateway or 'none'}")
        print()


def show_ports():
    """Show camera port reference."""
    print_header("\n  Camera Port Reference:\n")
    for port, desc in sorted(CAMERA_PORTS.items()):
        print(f"  {port:>5}  {desc}")
    print()


def run_web(args):
    """Launch the web dashboard UI."""
    from .webapp import create_app
    import webbrowser, threading

    app = create_app()
    host = args.host
    port = args.port
    url = f"http://127.0.0.1:{port}"

    print_header(f"\n  Camera Discovery Octopus — Web UI")
    print(f"\n  \033[1;32m{url}\033[0m\n")
    print(f"  Press Ctrl+C to stop\n")

    # Open browser unless suppressed (e.g. Electron opens it itself)
    if not getattr(args, 'no_browser', False):
        def _open():
            import time; time.sleep(1.2)
            webbrowser.open(url)
        threading.Thread(target=_open, daemon=True).start()
        print(f"  Opening browser automatically...")

    app.run(host=host, port=port, debug=False, threaded=True)


def run_subnets(args):
    """Manage subnet zones."""
    orchestrator = DiscoveryOrchestrator()

    if args.routes:
        routes = get_routes()
        print_header("\n  Routing Table:\n")
        print(f"  {'Destination':<18} {'Netmask':<18} {'Gateway':<18} {'Interface':<18} {'Metric':>6}")
        print(f"  {'─'*18} {'─'*18} {'─'*18} {'─'*18} {'─'*6}")
        for r in routes:
            print(f"  {r['destination']:<18} {r['netmask']:<18} {r['gateway']:<18} {r['interface']:<18} {r['metric']:>6}")
        print()
        return

    if args.probe:
        from .network import probe_subnet_connectivity
        print_info(f"\n  Probing {args.probe}...\n")
        result = probe_subnet_connectivity(args.probe)
        print(f"  Subnet:       {result['subnet']}")
        print(f"  Reachable:    {result['reachable_hosts']} host(s) in {result['tested_range']}")
        if result['found_ips']:
            print(f"  Found IPs:    {', '.join(result['found_ips'])}")
        if any(v > 0 for v in result['port_hits'].values()):
            print(f"  Port hits:")
            for port, count in result['port_hits'].items():
                if count > 0:
                    desc = CAMERA_PORTS.get(port, "")
                    print(f"    {port:>5}: {count} host(s) {desc}")
        print()
        return

    if args.add:
        zone = SubnetZone(
            subnet=args.add,
            label=args.label or "",
            gateway=args.gateway or "",
            method=args.method,
        )
        success = orchestrator.add_subnet_zone(zone)
        if success:
            print_success(f"  Added subnet zone: {args.add}")
        else:
            print_error(f"  Failed to add subnet zone: {args.add} (may need admin privileges)")
        print()
        return

    if args.remove:
        success = orchestrator.remove_subnet_zone(args.remove)
        if success:
            print_success(f"  Removed subnet zone: {args.remove}")
        else:
            print_warning(f"  Subnet zone not found: {args.remove}")
        print()
        return

    # List current subnet zones
    zones = orchestrator.subnet_zones
    if not zones:
        print_info("\n  No subnet zones configured.")
        print("  Use --add 192.168.88.0/24 to add a zone.\n")
        return

    print_header("\n  Subnet Zones:\n")
    for zone in zones.values():
        print(f"  {zone.subnet}")
        if zone.label:
            print(f"    Label:    {zone.label}")
        print(f"    Method:   {zone.method}")
        if zone.gateway:
            print(f"    Gateway:  {zone.gateway}")
        print(f"    Discovery: {'yes' if zone.discoverable else 'no'}  "
              f"Internet: {'blocked' if zone.internet_blocked else 'open'}  "
              f"DHCP: {zone.dhcp_mode}")
        if zone.notes:
            print(f"    Notes:    {zone.notes}")
        print()


def run_dpi(args):
    """Run DPI protocol-stage validation on a device."""
    if args.stages:
        print_header("\n  DPI Protocol Stages:\n")
        for s in DPI_STAGES:
            label = DPI_STAGE_LABELS.get(s, s)
            print(f"  {s:<14} {label}")
        print()
        return

    if not args.ip:
        print_error("  IP address is required. Usage: camera-discover dpi <ip>")
        sys.exit(1)

    ip = args.ip
    print_info(f"\n  Running DPI validation on {ip}...\n")

    orchestrator = DiscoveryOrchestrator()

    # Check if device is already known via ARP
    from .network import ping_host, get_arp_table
    reachable = ping_host(ip, 2000)
    if not reachable:
        print_warning(f"  {ip} is not reachable via ping. Results may be limited.\n")

    # Create a device entry and run DPI validation
    from .models import DiscoveredDevice
    device = DiscoveredDevice(ip=ip)

    # Quick discovery: ARP, port scan, ONVIF probe
    from .network import get_arp_table as _get_arp, test_tcp_port
    from .vendor import lookup_vendor
    from .discovery import scan_ports, send_onvif_probe, probe_rtsp

    # ARP lookup
    for entry in _get_arp():
        if entry["ip"] == ip:
            device.mac = entry["mac"]
            device.vendor = lookup_vendor(entry["mac"])
            device.discovery_methods.append("ARP")
            break

    # Port scan
    print(f"  Scanning ports...")
    device.open_ports = scan_ports(ip)

    # ONVIF probe
    print(f"  Probing ONVIF...")
    onvif_results = send_onvif_probe("")
    for od in onvif_results:
        if od.ip == ip:
            device.onvif_status = "found"
            if od.xaddrs:
                device.onvif_url = od.xaddrs[0]
            if od.model:
                device.model = od.model
            if od.manufacturer and device.vendor == "Unknown":
                device.vendor = od.manufacturer
            device.discovery_methods.append("ONVIF")
            break

    # RTSP probe
    if 554 in device.open_ports:
        print(f"  Probing RTSP...")
        rtsp_result = probe_rtsp(ip, 554)
        device.rtsp_status = "found" if rtsp_result.found else "error"
        if rtsp_result.found:
            device.rtsp_url = f"rtsp://{ip}:554/"

    # Web URL
    if 80 in device.open_ports:
        device.web_url = f"http://{ip}/"
    elif 8080 in device.open_ports:
        device.web_url = f"http://{ip}:8080/"
    elif 443 in device.open_ports:
        device.web_url = f"https://{ip}/"

    # Add to orchestrator and validate DPI
    orchestrator.devices[ip] = device
    orchestrator._validate_dpi_stages(ip)

    # Display results
    print_header(f"\n  DPI Validation Results for {ip}\n")
    print(f"  MAC:     {device.mac or 'unknown'}")
    print(f"  Vendor:  {device.vendor}")
    print(f"  Ports:   {', '.join(str(p) for p in device.open_ports) if device.open_ports else 'none'}")
    print(f"  Score:   {color_confidence(device.dpi_score)}")
    print()

    print(f"  {'Stage':<14} {'Status':<12} Detail")
    print(f"  {'─'*14} {'─'*12} {'─'*40}")
    for stage in DPI_STAGES:
        r = device.dpi_stages.get(stage)
        if not r:
            continue
        status_color = {
            "pass": "\033[32m",
            "fail": "\033[31m",
            "unchecked": "\033[33m",
            "na": "\033[90m",
        }.get(r.status, "")
        label = DPI_STAGE_LABELS.get(stage, stage)
        print(f"  {label:<14} {status_color}{r.status:<12}\033[0m {r.detail}")

    print()


def run_capture_pos(args):
    """Show or set capture position."""
    from .models import CAPTURE_POSITIONS

    orchestrator = DiscoveryOrchestrator()

    if args.set_position:
        orchestrator.set_capture_position(args.set_position)
        print_success(f"\n  Capture position set to: {args.set_position}")
        print()

    cp = orchestrator.capture_position
    print_header("\n  Capture Position:\n")
    print(f"  Position:  {cp.position}")
    print(f"  Label:     {CAPTURE_POSITIONS.get(cp.position, cp.position)}")
    print(f"  Unicast:   {'yes' if cp.can_see_unicast else 'no'}")
    print(f"  Broadcast: {'yes' if cp.can_see_broadcast else 'no'}")
    print(f"  Multicast: {'yes' if cp.can_see_multicast else 'no'}")
    print(f"  RTSP:      {'yes' if cp.can_see_rtsp else 'no'}")
    if cp.notes:
        print(f"  Notes:     {cp.notes}")

    if not cp.can_see_unicast or not cp.can_see_rtsp:
        print()
        print_warning("  Limited visibility! Consider:")
        print("    • Use a SPAN/mirror port on a managed switch")
        print("    • Use an inline tap between the PoE switch and NVR")
        print("    • Capture on the NVR's network interface directly")

    print()


def show_help():
    """Show main help with mode info."""
    print_header("\n  Camera Discovery Octopus\n")
    print("  Vendor-agnostic IP camera discovery tool\n")
    print("  Modes:")
    for key, desc in DISCOVERY_MODES.items():
        print(f"    {key:<14} {desc}")
    print()
    print("  Quick start:")
    print("    camera-discover scan                          # Listen-only mode")
    print("    camera-discover scan --mode sweep             # Active subnet scan")
    print("    camera-discover scan --mode fingerprint       # Full vendor fingerprint")
    print("    camera-discover scan --mode dpi               # Full DPI validation")
    print("    camera-discover scan --mode dhcp-trap         # DHCP trap (30s wait)")
    print("    camera-discover scan --no-dashboard           # CLI only (no TUI)")
    print("    camera-discover web                           # Launch web dashboard")
    print("    camera-discover web --port 8080               # Web UI on custom port")
    print("    camera-discover interfaces                    # Show network interfaces")
    print("    camera-discover ports                         # Show camera port reference")
    print("    camera-discover subnets                       # List subnet zones")
    print("    camera-discover subnets --add 192.168.88.0/24 # Add a subnet zone")
    print("    camera-discover subnets --probe 192.168.2.0/24 # Probe subnet connectivity")
    print("    camera-discover subnets --routes              # Show routing table")
    print("    camera-discover dpi 192.168.1.100             # DPI validate a device")
    print("    camera-discover dpi --stages                  # List DPI stage definitions")
    print("    camera-discover capture-pos                   # Show capture position")
    print("    camera-discover capture-pos --set span_port   # Set capture position")
    print()


# ─── Output helpers ──────────────────────────────────────────────────

def color_confidence(confidence: int) -> str:
    if confidence >= 70:
        return f"\033[32m{confidence}%\033[0m"
    elif confidence >= 40:
        return f"\033[33m{confidence}%\033[0m"
    else:
        return f"\033[90m{confidence}%\033[0m"


def print_header(text: str):
    print(f"\033[36m\033[1m{text}\033[0m")


def print_success(text: str):
    print(f"\033[32m{text}\033[0m")


def print_info(text: str):
    print(f"\033[34m{text}\033[0m")


def print_warning(text: str):
    print(f"\033[33m{text}\033[0m")


def print_error(text: str):
    print(f"\033[31m{text}\033[0m")
