"""CSV logging for CT Watcher alerts."""

from __future__ import annotations

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
    "api_ids",
    "keyword",
    "keyword_match_domains",
    "matched_keywords",
    "duo_status",
    "duo_a_records",
]

_LIST_FIELDS = {
    "all_domains",
    "nameservers_list",
    "all_ips",
    "non_cdn_ips",
    "confirmed_attacker_ip_matches",
    "api_ids",
    "keyword_match_domains",
    "matched_keywords",
}


def _ensure_csv_header(path: str) -> None:
    """Update a stale CSV header while preserving existing rows.

    Columns are only ever appended to the right, so an older header must be a
    prefix of ``_COLUMNS``. Old rows keep their shorter field counts; CSV
    readers treat the missing trailing values as blank.
    """
    with open(path, "r", newline="") as f:
        reader = csv.reader(f)
        try:
            header = next(reader)
        except StopIteration:
            return

    if header == _COLUMNS:
        return
    if header != _COLUMNS[: len(header)]:
        raise ValueError(f"{path}: existing CSV header is not a prefix of the current columns")

    with open(path, "r", newline="") as f:
        rows = list(csv.reader(f))
    rows[0] = _COLUMNS

    tmp_path = f"{path}.tmp"
    with open(tmp_path, "w", newline="") as f:
        csv.writer(f).writerows(rows)
    os.replace(tmp_path, path)


def log_alert_to_csv(alert: AlertInfo, log_path: str | None = None) -> None:
    """Append one alert row to the CSV log. Thread-safe."""
    path = log_path or _CSV_PATH
    row = asdict(alert)
    row["alert_timestamp"] = datetime.now(timezone.utc).isoformat()
    row["domain_count"] = len(alert.all_domains)
    row["api_id"] = alert.api_ids[0] if alert.api_ids else ""
    row["duo_status"] = "|".join(f"{aid}:{check.status}" for aid, check in alert.duo_checks.items())
    row["duo_a_records"] = "|".join(
        f"{aid}:{'+'.join(check.a_records)}" for aid, check in alert.duo_checks.items()
    )
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
    if row.get("keyword") is None:
        row["keyword"] = ""
    del row["target_info"]
    del row["not_before"]
    del row["duo_checks"]

    with _csv_lock:
        write_header = not os.path.isfile(path) or os.path.getsize(path) == 0
        if not write_header:
            _ensure_csv_header(path)
        with open(path, "a", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=_COLUMNS)
            if write_header:
                writer.writeheader()
            writer.writerow(row)
