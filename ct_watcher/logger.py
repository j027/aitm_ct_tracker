"""CSV logging for CT Watcher alerts."""

import csv
import os
import threading
from dataclasses import asdict
from datetime import datetime, timezone

from .models import AlertInfo

_CSV_PATH = "alerts.csv"
_csv_lock = threading.Lock()

_COLUMNS = [
    "alert_timestamp",
    "sha256",
    "serial_number",
    "certkit_url",
    "domain",
    "all_domains",
    "domain_count",
    "registrar",
    "reg_date",
    "is_cloudflare",
    "nameservers_list",
    "all_ips",
    "non_cdn_ips",
    "confirmed_attacker_ip_matches",
    "is_known_attacker",
    "target_name",
    "target_email",
    "api_id",
    "email_status_state",
    "email_status_details",
]

_LIST_FIELDS = {
    "all_domains",
    "nameservers_list",
    "all_ips",
    "non_cdn_ips",
    "confirmed_attacker_ip_matches",
}


def log_alert_to_csv(alert: AlertInfo, log_path: str | None = None) -> None:
    """Append one alert row to the CSV log. Thread-safe."""
    path = log_path or _CSV_PATH
    row = asdict(alert)
    row["alert_timestamp"] = datetime.now(timezone.utc).isoformat()
    row["domain_count"] = len(alert.all_domains)
    for key in _LIST_FIELDS:
        val = row.get(key)
        if val:
            row[key] = "|".join(val)
        else:
            row[key] = ""
    if alert.target_info:
        row["target_name"] = alert.target_info.get("name", "")
        row["target_email"] = alert.target_info.get("email", "")
    else:
        row["target_name"] = ""
        row["target_email"] = ""
    del row["target_info"]
    del row["not_before"]

    with _csv_lock:
        write_header = not os.path.isfile(path) or os.path.getsize(path) == 0
        with open(path, "a", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=_COLUMNS)
            if write_header:
                writer.writeheader()
            writer.writerow(row)
