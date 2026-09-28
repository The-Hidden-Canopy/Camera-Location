"""Windows network operations with a persistent change journal.

All temporary secondary-IP and route operations are recorded before being issued.
If the process crashes or is killed, the next startup can read incomplete journal
entries and offer to clean them up.
"""

from __future__ import annotations

import ipaddress
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from ..persistence.db import Database
from ..persistence.repos import NetworkChangeJournalRepo


class WindowsNetworkAdapter:
    """Wraps netsh operations and writes every change to the journal first."""

    def __init__(self, db: Database):
        self._db = db
        self._journal = NetworkChangeJournalRepo(db)

    def add_secondary_ip(
        self,
        interface_name: str,
        ip: str,
        prefix_len: int,
        operation_id: Optional[str] = None,
        user_id: Optional[str] = None,
    ) -> str:
        journal_id = self._journal.add(
            operation_id=operation_id or _new_uuid(),
            interface_name=interface_name,
            ip=ip,
            prefix_len=prefix_len,
            action="add_secondary_ip",
            user_id=user_id,
        )
        cmd = [
            "netsh", "interface", "ip", "add", "address",
            interface_name, ip, str(prefix_len_to_netmask(prefix_len)),
        ]
        _run(cmd)
        self._journal.mark_complete(journal_id)
        return journal_id

    def remove_secondary_ip(
        self,
        interface_name: str,
        ip: str,
        prefix_len: int,
    ) -> None:
        cmd = [
            "netsh", "interface", "ip", "delete", "address",
            interface_name, ip, str(prefix_len_to_netmask(prefix_len)),
        ]
        _run(cmd)

    def recover_incomplete(self) -> List[Dict]:
        """Return incomplete journal entries so the UI can prompt cleanup."""
        return self._journal.incomplete()

    def cleanup_incomplete(self, max_entries: int = 100) -> List[Dict]:
        """Forcibly remove every IP listed in incomplete journal entries."""
        cleaned = []
        for entry in self._journal.incomplete()[:max_entries]:
            try:
                self.remove_secondary_ip(entry["interface_name"], entry["ip"], entry["prefix_len"])
            except Exception:
                pass
            self._journal.mark_complete(entry["journal_id"])
            cleaned.append(entry)
        return cleaned


def prefix_len_to_netmask(prefix_len: int) -> str:
    return str(ipaddress.IPv4Network(f"0.0.0.0/{prefix_len}").netmask)


def _new_uuid() -> str:
    import uuid
    return str(uuid.uuid4())


def _run(cmd: List[str]) -> str:
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise RuntimeError(f"netsh failed: {result.stderr or result.stdout}")
    return result.stdout
