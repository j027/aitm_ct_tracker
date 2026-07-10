#!/usr/bin/env python3
"""Check known attacker domains for expiration via WHOIS/RDAP.

Usage:
    python expiry_checker.py              # check all domains, move expired ones
    python expiry_checker.py --dry-run    # preview only, no file changes
"""

import argparse
import os
import sys
from datetime import datetime, timezone
from typing import List, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ct_watcher.rdap import get_domain_status
from ct_watcher.config import KNOWN_DOMAINS_FILE, EXPIRED_DOMAINS_FILE


def _parse_date(raw: str | None) -> datetime | None:
    """Parse an ISO 8601 or YYYY-MM-DD date string to a timezone-aware datetime."""
    if not raw:
        return None
    raw = raw.strip()
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            dt = datetime.strptime(raw, fmt)
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _read_domains(filepath: str) -> list[Tuple[str, str]]:
    """Read a defanged domain file, return [(un_defanged, defanged)].

    Skips comments (``#``) and blank lines.
    """
    entries = []
    if not os.path.exists(filepath):
        return entries
    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            defanged = line
            un_defanged = line.replace("[.]", ".").replace("[dot]", ".").lower()
            entries.append((un_defanged, defanged))
    return entries


def _write_domains(filepath: str, domains: List[str]) -> None:
    """Write a list of defanged domains to a file."""
    with open(filepath, "w") as f:
        if domains:
            for d in domains:
                f.write(f"{d}\n")


def _defang(domain: str) -> str:
    """Defang a domain by replacing . with [.]."""
    return domain.replace(".", "[.]")


def main() -> None:
    parser = argparse.ArgumentParser(description="Check known attacker domains for expiration")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview results without modifying files",
    )
    args = parser.parse_args()

    entries = _read_domains(KNOWN_DOMAINS_FILE)
    if not entries:
        print(f"[*] No domains found in {KNOWN_DOMAINS_FILE}")
        return

    now = datetime.now(timezone.utc)

    active: List[Tuple[str, str, str]] = []
    expired: List[Tuple[str, str]] = []
    available: List[Tuple[str, str]] = []
    unknown: List[Tuple[str, str]] = []

    for i, (un_defanged, defanged) in enumerate(entries, 1):
        print(f"\r[~] Checking {i}/{len(entries)}: {un_defanged}   ", end="", flush=True)
        status, exp_date_raw = get_domain_status(un_defanged)

        if status == "registered":
            exp_dt = _parse_date(exp_date_raw)
            if exp_dt is None:
                unknown.append((un_defanged, defanged))
            elif exp_dt <= now:
                expired.append((un_defanged, defanged))
            else:
                remain = (exp_dt - now).days
                active.append((un_defanged, defanged, f"{exp_dt.strftime('%Y-%m-%d')} ({remain}d)"))
        elif status == "available":
            available.append((un_defanged, defanged))
        else:
            unknown.append((un_defanged, defanged))

    print("\n")

    active.sort()
    expired.sort()
    available.sort()
    unknown.sort()

    defanged_expired = [d[1] for d in expired]
    defanged_available = [d[1] for d in available]
    all_to_move = defanged_expired + defanged_available

    old_expired = [d[1] for d in _read_domains(EXPIRED_DOMAINS_FILE)]
    combined_expired = sorted(set(old_expired + all_to_move), key=str.lower)

    if active:
        print(f"ACTIVE ({len(active)}):")
        for d, orig, exp_str in active:
            print(f"  {orig}  → expires {exp_str}")
        print()

    if expired:
        print(f"EXPIRED ({len(expired)}):")
        for d, orig in expired:
            print(f"  {orig}")
        print()

    if available:
        print(f"AVAILABLE ({len(available)}) — no longer registered:")
        for d, orig in available:
            print(f"  {orig}")
        print()

    if unknown:
        print(f"UNKNOWN ({len(unknown)}) — lookup failed:")
        for d, orig in unknown:
            print(f"  {orig}")
        print()

    keeps = [d[1] for d in active] + [d[1] for d in unknown]
    keeps.sort(key=str.lower)

    if all_to_move:
        print(f"→ {len(all_to_move)} domains will be moved to {EXPIRED_DOMAINS_FILE}")
        print(f"→ {len(keeps)} domains remain in {KNOWN_DOMAINS_FILE}")
        print(f"→ {len(combined_expired)} total in {EXPIRED_DOMAINS_FILE}")
    else:
        print("→ No domains to move.")

    if args.dry_run:
        print("\n[*] --dry-run: no files modified.")
        return

    if all_to_move:
        _write_domains(EXPIRED_DOMAINS_FILE, combined_expired)
        _write_domains(KNOWN_DOMAINS_FILE, keeps)
        print("\n[*] Done. Restart the watcher for changes to take effect.")
    else:
        print("\n[*] No changes needed.")


if __name__ == "__main__":
    main()
