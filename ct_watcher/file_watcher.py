"""Background file watcher for auto-reloading config files at runtime."""

import asyncio
import os

from .config import (
    KNOWN_DOMAINS_FILE,
    KNOWN_IPS_FILE,
    TARGETS_FILE,
    WATCHED_ORG_IDS_FILE,
    EMAIL_TEMPLATE_FILE,
)
from .state import state
from .loaders import (
    load_known_attacker_domains,
    load_known_attacker_ips,
    load_target_mapping,
    load_watched_org_ids,
    load_email_template,
)

CHECK_INTERVAL = 5

_WATCHED = (
    (KNOWN_DOMAINS_FILE, "known_attacker_domains", load_known_attacker_domains, False),
    (KNOWN_IPS_FILE, "known_attacker_ips", load_known_attacker_ips, False),
    (TARGETS_FILE, None, load_target_mapping, True),
    (WATCHED_ORG_IDS_FILE, "watched_org_ids", load_watched_org_ids, False),
    (EMAIL_TEMPLATE_FILE, "email_template", load_email_template, False),
)


async def start_file_watcher() -> None:
    mtimes = {}
    for filepath in (row[0] for row in _WATCHED):
        if os.path.exists(filepath):
            mtimes[filepath] = os.path.getmtime(filepath)

    while True:
        await asyncio.sleep(CHECK_INTERVAL)
        for filepath, attr, loader, is_dual in _WATCHED:
            try:
                if not os.path.exists(filepath):
                    continue
                new_mtime = os.path.getmtime(filepath)
                if filepath in mtimes and new_mtime <= mtimes[filepath]:
                    continue
                mtimes[filepath] = new_mtime

                if is_dual:
                    duo, kw = await asyncio.to_thread(loader)
                    state.target_mapping = duo
                    state.keyword_targets = kw
                else:
                    result = await asyncio.to_thread(loader)
                    setattr(state, attr, result)
            except Exception:
                pass
