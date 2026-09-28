"""TUI Dashboard using curses for interactive camera discovery"""

from __future__ import annotations

# curses ships with Python on Linux/macOS but NOT with stock Windows Python.
# Import defensively so this module is always importable; the TUI simply
# refuses to start (with a clear message) when curses is missing, and the
# CLI falls back automatically. The web UI is unaffected.
try:
    import curses
    _CURSES_ERR = ""
except Exception as _e:           # ModuleNotFoundError: No module named '_curses'
    curses = None
    _CURSES_ERR = str(_e)

import threading
import time
from datetime import datetime, timezone
from typing import List, Optional

from .models import DiscoveredDevice
from .orchestrator import DiscoveryOrchestrator, DiscoveryProgress
from .network import NetworkInterface


class Dashboard:
    """Curses-based TUI dashboard for camera discovery."""

    def __init__(self, orchestrator: DiscoveryOrchestrator):
        self.orchestrator = orchestrator
        self.devices: List[DiscoveredDevice] = []
        self.selected_interface: Optional[NetworkInterface] = None
        self._running = False
        self._status_msg = "Ready"
        self._progress = 0
        self._log_lines: List[str] = []
        self._scroll_offset = 0
        self._selected_row = 0
        self._log_scroll = 0

    def set_interface(self, iface: NetworkInterface):
        self.selected_interface = iface
        self.orchestrator.set_interface(iface)

    def run(self, mode: str):
        """Start the curses TUI. Raises a clear error (caught by the CLI,
        which then falls back to plain CLI mode) when curses is unavailable
        — e.g. stock Windows Python has no _curses module."""
        if curses is None:
            raise RuntimeError(
                f"TUI needs the 'curses' module which is not available "
                f"({_CURSES_ERR}). Use 'camera-discover scan --no-dashboard' "
                f"or the web UI: 'camera-discover web'.")
        curses.wrapper(self._main_loop, mode)

    def _main_loop(self, stdscr, mode: str):
        curses.curs_set(0)
        stdscr.nodelay(True)
        stdscr.timeout(100)

        # Colors
        curses.start_color()
        curses.init_pair(1, curses.COLOR_CYAN, curses.COLOR_BLACK)
        curses.init_pair(2, curses.COLOR_GREEN, curses.COLOR_BLACK)
        curses.init_pair(3, curses.COLOR_YELLOW, curses.COLOR_BLACK)
        curses.init_pair(4, curses.COLOR_RED, curses.COLOR_BLACK)
        curses.init_pair(5, curses.COLOR_WHITE, curses.COLOR_BLUE)
        curses.init_pair(6, curses.COLOR_MAGENTA, curses.COLOR_BLACK)
        curses.init_pair(7, curses.COLOR_BLACK, curses.COLOR_CYAN)

        self._running = True

        # Start discovery in background
        self.orchestrator.on_progress = self._on_progress
        self.orchestrator.on_device_found = self._on_device_found
        self.orchestrator.on_device_updated = self._on_device_updated

        discovery_thread = threading.Thread(
            target=self._run_discovery, args=(mode,), daemon=True
        )
        discovery_thread.start()

        while self._running:
            stdscr.clear()
            h, w = stdscr.getmaxyx()

            self._draw_header(stdscr, h, w)
            self._draw_progress(stdscr, h, w)
            self._draw_device_table(stdscr, h, w)
            self._draw_log(stdscr, h, w)
            self._draw_help(stdscr, h, w)

            stdscr.refresh()

            # Handle input
            try:
                key = stdscr.getch()
            except Exception:
                key = -1

            if key == ord('q') or key == 27:  # q or ESC
                self._running = False
                self.orchestrator.stop()
                break
            elif key == ord('1'):
                self._restart_discovery("listen")
            elif key == ord('2'):
                self._restart_discovery("dhcp-trap")
            elif key == ord('3'):
                self._restart_discovery("sweep")
            elif key == ord('4'):
                self._restart_discovery("fingerprint")
            elif key == ord('e'):
                self._export_results()
            elif key == ord('i'):
                self._show_interfaces(stdscr)
            elif key == curses.KEY_UP:
                self._selected_row = max(0, self._selected_row - 1)
            elif key == curses.KEY_DOWN:
                self._selected_row = min(len(self.devices) - 1, self._selected_row + 1)
            elif key == curses.KEY_PPAGE:
                self._scroll_offset = max(0, self._scroll_offset - 10)
            elif key == curses.KEY_NPAGE:
                self._scroll_offset += 10

        self.orchestrator.stop()

    def _draw_header(self, stdscr, h, w):
        mode_str = self.selected_interface.name if self.selected_interface else "---"
        ip_str = self.selected_interface.ip if self.selected_interface else "---"
        stdscr.addstr(0, 0, " CAMERA DISCOVERY OCTOPUS", curses.color_pair(1) | curses.A_BOLD)
        stdscr.addstr(0, 35, f" Interface: {mode_str} ({ip_str})  |  Devices: {len(self.devices)}", curses.color_pair(3))
        stdscr.addstr(1, 0, f" {self._status_msg}", curses.color_pair(2))

    def _draw_progress(self, stdscr, h, w):
        y = 2
        bar_width = w - 4
        filled = int(bar_width * self._progress / 100)
        stdscr.addstr(y, 0, " [", curses.color_pair(1))
        stdscr.addstr(y, 2, "=" * filled, curses.color_pair(1))
        stdscr.addstr(y, 2 + filled, " " * (bar_width - filled), curses.color_pair(0))
        stdscr.addstr(y, 2 + bar_width, "]", curses.color_pair(1))
        stdscr.addstr(y, 2 + bar_width + 2, f"{self._progress}%", curses.color_pair(1))

    def _draw_device_table(self, stdscr, h, w):
        y_start = 4
        table_height = h - 12

        # Headers
        headers = f" {'IP':<16} {'MAC':<18} {'Vendor':<18} {'Model':<12} {'Ports':<20} {'Proto':<12} {'ONVIF':<8} {'Score':<6}"
        stdscr.addstr(y_start, 0, headers, curses.color_pair(5))
        stdscr.addstr(y_start, len(headers), " " * (w - len(headers) - 1), curses.color_pair(5))

        # Device rows
        visible_devices = self.devices[self._scroll_offset:self._scroll_offset + table_height]
        for i, d in enumerate(visible_devices):
            row_idx = i + self._scroll_offset
            y = y_start + 1 + i

            if y >= h - 8:
                break

            score_str = f"{d.camera_confidence}%"   # Gap 11
            ports_str = ",".join(str(p) for p in d.open_ports[:6])
            proto_str = ",".join(d.protocols[:3])

            line = f" {d.ip:<16} {d.mac or '---':<18} {d.vendor:<18} {d.model or '---':<12} {ports_str:<20} {proto_str:<12} {d.onvif_status:<8} {score_str:<6}"

            if row_idx == self._selected_row:
                stdscr.addstr(y, 0, line[:w-1], curses.A_REVERSE)
            else:
                # Color code by confidence
                color = 0
                if d.camera_confidence >= 70:
                    color = curses.color_pair(2)
                elif d.camera_confidence >= 40:
                    color = curses.color_pair(3)
                elif d.camera_confidence > 0:
                    color = curses.color_pair(4)
                stdscr.addstr(y, 0, line[:w-1], color)

        # Show selected device details
        if 0 <= self._selected_row < len(self.devices):
            d = self.devices[self._selected_row]
            detail_y = h - 8
            stdscr.addstr(detail_y, 0, "─" * w, curses.color_pair(1))
            stdscr.addstr(detail_y + 1, 0, f" Selected: {d.ip} — {d.vendor} {d.model}", curses.color_pair(1) | curses.A_BOLD)
            if d.web_url:
                stdscr.addstr(detail_y + 2, 2, f"Web:   {d.web_url}", curses.color_pair(6))
            if d.rtsp_url:
                stdscr.addstr(detail_y + 3, 2, f"RTSP:  {d.rtsp_url}", curses.color_pair(6))
            if d.onvif_url:
                stdscr.addstr(detail_y + 4, 2, f"ONVIF: {d.onvif_url}", curses.color_pair(6))
            if d.open_ports:
                stdscr.addstr(detail_y + 5, 2, f"Ports: {', '.join(str(p) for p in d.open_ports)}", curses.color_pair(3))

    def _draw_log(self, stdscr, h, w):
        log_y = h - 2
        visible_logs = self._log_lines[-1:] if self._log_lines else [""]
        for i, line in enumerate(visible_logs[-1:]):
            text = line[:w-1]
            stdscr.addstr(log_y, 0, text, curses.color_pair(2))

    def _draw_help(self, stdscr, h, w):
        help_y = h - 1
        stdscr.addstr(help_y, 0, " [1-4] Mode  [E] Export  [I] Interfaces  [Up/Dn] Select  [Q] Quit", curses.color_pair(5))

    def _on_progress(self, p: DiscoveryProgress):
        self._status_msg = f"[{p.phase}] {p.message}"
        self._progress = int(p.current / max(p.total, 1) * 100)
        self._log_lines.append(f"[{p.phase}] {p.message}")

    def _on_device_found(self, device: DiscoveredDevice):
        self._log_lines.append(f"  Found: {device.ip} ({device.vendor})")

    def _on_device_updated(self, device: DiscoveredDevice):
        # Update or add device in list
        for i, d in enumerate(self.devices):
            if d.ip == device.ip:
                self.devices[i] = device
                return
        self.devices.append(device)

    def _run_discovery(self, mode: str):
        try:
            self.orchestrator.run(mode)
            self._status_msg = f"Discovery complete. Found {len(self.orchestrator.discovered_devices)} device(s)."
            self._progress = 100
        except Exception as e:
            self._status_msg = f"Error: {e}"
            self._log_lines.append(f"ERROR: {e}")

    def _restart_discovery(self, mode: str):
        self.devices.clear()
        self._selected_row = 0
        self._scroll_offset = 0
        self._progress = 0
        # _full_reset() wipes devices + all triage queues; run() will call it
        # again with clear=True (the default) but calling it here ensures the
        # TUI device list and the orchestrator are in sync before the thread starts.
        self.orchestrator._full_reset()

        thread = threading.Thread(
            target=self._run_discovery, args=(mode,), daemon=True
        )
        thread.start()

    def _export_results(self):
        from .report import export_to_csv, generate_summary
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        filename = f"camera-discovery-{timestamp}.csv"
        try:
            export_to_csv(self.devices, filename)
            self._log_lines.append(f"Exported to {filename}")
        except Exception as e:
            self._log_lines.append(f"Export failed: {e}")

    def _show_interfaces(self, stdscr):
        interfaces = self.orchestrator.select_interface()
        items = [f"{i.name} | {i.ip} | {i.mac} | {i.iface_type}" for i in interfaces]

        # Simple selection UI
        selected = 0
        while True:
            y = 5
            stdscr.clear()
            stdscr.addstr(2, 2, "Select Network Interface:", curses.color_pair(1) | curses.A_BOLD)
            stdscr.addstr(3, 2, "Use Up/Down to select, Enter to confirm, Esc to cancel", curses.color_pair(3))

            for i, item in enumerate(items):
                if i == selected:
                    stdscr.addstr(y + i, 2, f" > {item}", curses.A_REVERSE)
                else:
                    stdscr.addstr(y + i, 2, f"   {item}")

            stdscr.refresh()

            key = stdscr.getch()
            if key == curses.KEY_UP:
                selected = max(0, selected - 1)
            elif key == curses.KEY_DOWN:
                selected = min(len(items) - 1, selected + 1)
            elif key == ord('\n') or key == curses.KEY_ENTER:
                if interfaces:
                    self.set_interface(interfaces[selected])
                break
            elif key == 27:  # ESC
                break
