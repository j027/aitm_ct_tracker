"""Main entry point for CT Watcher."""

import asyncio
from .config import DISCORD_WEBHOOK, APPRISE_URLS, EMAIL_ENABLED, SMTP_ENABLED, CDN_NETWORKS
from .state import state
from .loaders import (
    load_known_attacker_domains,
    load_known_attacker_ips,
    load_target_mapping,
    load_email_template,
    load_attacker_ips,
    load_watched_org_ids,
)
from .cdn_fetcher import load_cdn_networks, log_cdn_stats
from .websocket_client import run_websocket_client
from .console import log


def main() -> None:
    """Main entry point."""
    if not (DISCORD_WEBHOOK or APPRISE_URLS or (EMAIL_ENABLED and SMTP_ENABLED)):
        log("[*] No notification channels configured — alerts will be logged only")

    # Load all configuration files
    state.known_attacker_domains = load_known_attacker_domains()
    state.known_attacker_ips = load_known_attacker_ips()
    state.target_mapping, state.keyword_targets = load_target_mapping()
    state.email_template = load_email_template()
    state.attacker_ips_data = load_attacker_ips()
    state.watched_org_ids = load_watched_org_ids()

    # Load dynamic CDN ranges
    provider_ranges, networks = load_cdn_networks()
    log_cdn_stats(provider_ranges)
    CDN_NETWORKS.extend(networks)

    # Start the WebSocket client
    asyncio.run(run_websocket_client())


if __name__ == "__main__":
    main()
