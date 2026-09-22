"""Global state management for CT Watcher."""

import threading
from dataclasses import dataclass, field
from typing import Dict, Set, Any, Tuple


@dataclass
class WatcherState:
    """Holds all mutable state for the watcher."""

    # Deduplication sets
    alerted_certificates: Set[str] = field(default_factory=set)

    # Known data (loaded from files)
    known_attacker_domains: Set[str] = field(default_factory=set)
    known_attacker_ips: Set[str] = field(default_factory=set)
    target_mapping: Dict[str, Dict[str, str]] = field(default_factory=dict)
    keyword_targets: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    email_template: str = ""
    attacker_ips_data: Dict[str, Any] = field(
        default_factory=lambda: {"ips": {}, "last_updated": None}
    )
    watched_org_ids: Set[str] = field(default_factory=set)

    # Stats
    cert_count: int = 0
    total_alerts_count: int = 0

    # Reconnection
    reconnect_delay: int = 1

    # Locks
    lock: threading.Lock = field(default_factory=threading.Lock)
    ip_save_lock: threading.Lock = field(default_factory=threading.Lock)
    stats_lock: threading.Lock = field(default_factory=threading.Lock)

    def clear_alerted_certificates(self):
        """Clear alerted certificates set."""
        self.alerted_certificates.clear()

    def increment_cert_count(self):
        """Count one processed certificate."""
        with self.stats_lock:
            self.cert_count += 1

    def increment_alerts_count(self):
        """Count one dispatched alert."""
        with self.stats_lock:
            self.total_alerts_count += 1

    def snapshot_and_reset_stats(self) -> Tuple[int, int]:
        """Return (certs since last snapshot, cumulative alerts) and reset cert count."""
        with self.stats_lock:
            cert_count = self.cert_count
            self.cert_count = 0
            return cert_count, self.total_alerts_count


# Global state instance
state = WatcherState()
